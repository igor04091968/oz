#![cfg_attr(windows, windows_subsystem = "windows")]

//! ОЗ — небольшой оркестратор заявок на удаленную работу.
//!
//! Программа имеет два сценария запуска:
//! - CLI для проверки заявок;
//! - GUI для настройки подключений, фонового опроса MSSQL и click-to-call.
//!
//! Секреты намеренно не записываются в TOML и не попадают в журнал. GUI хранит
//! их в системном хранилище учетных данных, а CLI получает их через переменные
//! окружения.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::{Args, Parser, Subcommand, ValueEnum};
use rusqlite::{Connection, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tiberius::{Client as MssqlClient, Config as MssqlConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{info, warn};
use xphone::{Codec as SipCodec, Phone, PhoneBuilder};

#[derive(Parser)]
#[command(version, about = "Отслеживание заявок и XMPP/Miranda-интеграция")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

// Подкоманды разделены по назначению: process-requests проверяет заявки,
// report формирует сводку за день или неделю, gui запускает интерфейс.
#[derive(Subcommand)]
enum Command {
    ProcessRequests(CommonArgs),
    Report(ReportArgs),
    Gui,
}

// Общий аргумент конфигурации. Переменная окружения удобна для запуска из
// Планировщика заданий или внешнего служебного скрипта.
#[derive(Args, Clone)]
struct CommonArgs {
    #[arg(long, env = "ORCH_CONFIG", default_value = "config.toml")]
    config: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReportPeriod {
    Day,
    Week,
}

#[derive(Args, Clone)]
struct ReportArgs {
    #[arg(long, env = "ORCH_CONFIG", default_value = "config.toml")]
    config: String,
    /// Опорная дата в формате YYYY-MM-DD; для week берется предыдущий 6-дневный период.
    #[arg(long)]
    date: String,
    #[arg(long, value_enum, default_value_t = ReportPeriod::Day)]
    period: ReportPeriod,
}

// Эти структуры описывают runtime-конфигурацию. Они не содержат паролей и
// токенов: вместо них хранятся имена переменных окружения.
#[derive(Debug, Deserialize)]
struct AppConfig {
    runtime: RuntimeConfig,
    mssql: SqlConfig,
    requests: Option<RequestsConfig>,
}

#[derive(Debug, Deserialize)]
struct RuntimeConfig {
    #[serde(rename = "interval_seconds")]
    _interval_seconds: u64,
    audit_db_path: String,
}

#[derive(Debug, Deserialize)]
struct SqlConfig {
    connection_string_env: String,
    default_connection_string: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RequestsConfig {
    query_file: String,
    mark_unapproved_as_seen: bool,
}

#[derive(Debug, Clone)]
struct RemoteWorkRequest {
    request_num: String,
    requester: String,
    por_neisp: i32,
}

// Точка входа выбирает GUI, если аргументы не переданы. Это позволяет запускать
// собранный oz.exe двойным щелчком с рабочего стола.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let cli = Cli::parse();

    match cli.command {
        None => run_gui(),
        Some(Command::ProcessRequests(args)) => {
            let config = load_config(&args.config)?;
            process_requests(&config).await
        }
        Some(Command::Report(args)) => {
            let config = load_config(&args.config)?;
            report_requests(&config, args.period, &args.date).await
        }
        Some(Command::Gui) => run_gui(),
    }
}

const GUI_SERVICE: &str = "oz";
const MSSQL_SECRET: &str = "mssql-connection-string";
const XMPP_SECRET: &str = "xmpp-account-password";
const SIP_SECRET: &str = "sip-account-password";
const LEGACY_SIP_SECRET: &str = "sip-1001-password";

// Настройки GUI сериализуются в gui-settings.toml. Поля с паролями отсутствуют:
// реальные значения загружаются из Credential Manager только в память процесса.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct GuiSettings {
    config_path: String,
    poll_interval_seconds: String,
    poll_enabled: bool,
    sql_server: String,
    sql_port: String,
    sql_database: String,
    sql_user: String,
    query_file: String,
    audit_db_path: String,
    xmpp_server: String,
    xmpp_port: String,
    xmpp_account: String,
    xmpp_resource: String,
    xmpp_recipient: String,
    xmpp_call_recipient: String,
    xmpp_caller_extension: String,
    call_target: String,
    sip_enabled: bool,
    sip_server: String,
    sip_port: String,
    sip_username: String,
    report_date: String,
    report_period: String,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            config_path: "config.toml".to_owned(),
            poll_interval_seconds: "60".to_owned(),
            poll_enabled: true,
            sql_server: "srv-db".to_owned(),
            sql_port: "1433".to_owned(),
            sql_database: "rd_all".to_owned(),
            sql_user: String::new(),
            query_file: "sql/remote_work_requests.sql".to_owned(),
            audit_db_path: "audit.sqlite3".to_owned(),
            xmpp_server: "jabber.syk.sevnb.ru".to_owned(),
            xmpp_port: "5222".to_owned(),
            xmpp_account: "oz@dns.sevnb.ru".to_owned(),
            xmpp_resource: "oz".to_owned(),
            xmpp_recipient: String::new(),
            xmpp_call_recipient: "pbx@dns.sevnb.ru".to_owned(),
            xmpp_caller_extension: "1001".to_owned(),
            call_target: String::new(),
            sip_enabled: true,
            sip_server: "10.33.1.82".to_owned(),
            sip_port: "5060".to_owned(),
            sip_username: "1001".to_owned(),
            report_date: "2026-09-01".to_owned(),
            report_period: "day".to_owned(),
        }
    }
}

struct GuiApp {
    settings: GuiSettings,
    mssql_password: String,
    xmpp_password: String,
    sip_password: String,
    remember_secrets: bool,
    status: String,
    running: bool,
    stop: Arc<AtomicBool>,
    sip_stop: Arc<AtomicBool>,
    sip_running: bool,
    sip_ready: bool,
    result_rx: Receiver<String>,
    result_tx: Sender<String>,
}

impl GuiApp {
    // При старте читаем обычные параметры и отдельно пытаемся восстановить
    // секреты из системного хранилища. Отсутствующий секрет не блокирует GUI:
    // пользователь сможет ввести его вручную.
    fn new() -> Self {
        let settings = load_gui_settings().unwrap_or_default();
        let mssql_password = read_secret(MSSQL_SECRET).unwrap_or_default();
        let xmpp_password = read_secret(XMPP_SECRET).unwrap_or_default();
        let sip_password = read_secret(SIP_SECRET)
            .or_else(|_| read_secret(LEGACY_SIP_SECRET))
            .unwrap_or_default();
        let (result_tx, result_rx) = mpsc::channel();
        Self {
            settings,
            mssql_password,
            xmpp_password,
            sip_password,
            remember_secrets: true,
            status: "Готово. Ожидание проверки заявок.".to_owned(),
            running: false,
            stop: Arc::new(AtomicBool::new(false)),
            sip_stop: Arc::new(AtomicBool::new(false)),
            sip_running: false,
            sip_ready: false,
            result_rx,
            result_tx,
        }
    }

    fn start(&mut self) {
        if self.running {
            return;
        }
        self.stop = Arc::new(AtomicBool::new(false));
        if let Err(error) = self.save_settings() {
            self.status = format!("Ошибка сохранения: {error:#}");
            return;
        }
        if self.settings.sip_enabled && !self.sip_password.is_empty() {
            self.start_virtual_sip();
        }
        let settings = self.settings.clone();
        let mssql_password = self.mssql_password.clone();
        let xmpp_password = self.xmpp_password.clone();

        let tx = self.result_tx.clone();
        let config_path = settings.config_path.clone();
        let stop = Arc::clone(&self.stop);
        self.running = true;
        self.status = "Фоновый опрос запущен.".to_owned();
        // Фоновый поток не блокирует egui. Результаты каждой проверки возвращаются
        // в GUI через канал, а stop-флаг позволяет корректно завершить поток.
        thread::spawn(move || {
            let mut notified_fingerprint = String::new();
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let message = run_gui_poll(
                    &settings,
                    &config_path,
                    &mssql_password,
                    &xmpp_password,
                    &mut notified_fingerprint,
                );
                let _ = tx.send(message);
                if !settings.poll_enabled {
                    break;
                }
                let interval = settings
                    .poll_interval_seconds
                    .parse::<u64>()
                    .unwrap_or(60)
                    .max(5);
                for _ in 0..interval {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }

    fn save_settings(&mut self) -> Result<()> {
        save_gui_settings(&self.settings)?;
        write_runtime_config(&self.settings)?;
        if self.remember_secrets {
            save_secret(MSSQL_SECRET, &self.mssql_password)?;
            save_secret(XMPP_SECRET, &self.xmpp_password)?;
            save_secret(SIP_SECRET, &self.sip_password)?;
        }
        self.status = "Настройки сохранены.".to_owned();
        Ok(())
    }

    // Виртуальный аппарат должен быть зарегистрирован до отправки команды
    // XMPP: АТС сначала вызывает его, а после автоответа набирает цель.
    fn start_virtual_sip(&mut self) {
        if self.sip_running {
            return;
        }
        let server = self.settings.sip_server.trim().to_owned();
        let port = match self.settings.sip_port.trim().parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                self.status = "SIP не запущен: неверный порт АТС".to_owned();
                return;
            }
        };
        let username = self.settings.sip_username.trim().to_owned();
        let password = self.sip_password.clone();
        if server.is_empty() || username.is_empty() || password.is_empty() {
            self.status = "SIP не запущен: заполните сервер, номер и Secret".to_owned();
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.sip_stop = Arc::clone(&stop);
        self.sip_running = true;
        self.sip_ready = false;
        let tx = self.result_tx.clone();
        thread::spawn(move || {
            let config = PhoneBuilder::new()
                .credentials(&username, &password, &server)
                .port(port)
                .codecs(vec![SipCodec::PCMA, SipCodec::TelephoneEvent])
                .rtp_ports(10000, 20000)
                .with_nat(true)
                .nat_keepalive(Duration::from_secs(20))
                .user_agent("OZ-virtual-phone/0.1")
                .build();
            let phone = Phone::new(config);
            phone.on_incoming(|call| {
                if let Err(error) = call.accept() {
                    warn!(error = %error, "virtual SIP auto-answer failed");
                }
            });
            match phone.connect() {
                Ok(()) => {
                    let _ = tx.send(format!(
                        "OZ_FOCUS\nВиртуальный SIP-телефон {username} зарегистрирован; автоответ включен."
                    ));
                    while !stop.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_secs(1));
                    }
                    let _ = phone.disconnect();
                }
                Err(error) => {
                    let _ = tx.send(format!("SIP-регистрация не выполнена: {error}"));
                }
            }
        });
    }

    fn start_call(&mut self) {
        let target = self.settings.call_target.trim().to_owned();
        if let Err(error) = validate_call_target(&target) {
            self.status = format!("Звонок не отправлен: {error}");
            return;
        }
        if self.settings.sip_enabled && (!self.sip_running || !self.sip_ready) {
            if !self.sip_running {
                self.start_virtual_sip();
            }
            self.status =
                "Виртуальный SIP еще регистрируется; повторите дозвон после статуса Registered."
                    .to_owned();
            return;
        }
        let server = self.settings.xmpp_server.clone();
        let port = self.settings.xmpp_port.clone();
        let account = self.settings.xmpp_account.clone();
        let resource = self.settings.xmpp_resource.clone();
        let password = self.xmpp_password.clone();
        let recipient = self.settings.xmpp_call_recipient.clone();
        let tx = self.result_tx.clone();
        self.status = format!("Отправка команды звонка на {target}...");
        // Сетевой XMPP-сеанс выполняется вне потока интерфейса, иначе задержка
        // соединения или авторизации временно заморозит окно.
        thread::spawn(move || {
            let result = send_xmpp_call_blocking(
                &server, &port, &account, &resource, &password, &recipient, &target,
            );
            let message = match result {
                Ok(()) => {
                    format!(
                        "OZ_FOCUS\nКоманда звонка отправлена на {target} от источника {}.",
                        resource
                    )
                }
                Err(error) => format!("Звонок не отправлен: {error}"),
            };
            let _ = tx.send(message);
        });
    }

    fn start_xmpp_test(&mut self) {
        let recipient = self.settings.xmpp_recipient.trim().to_owned();
        if recipient.is_empty() {
            self.status = "Тест XMPP не запущен: укажите JID получателя уведомлений".to_owned();
            return;
        }
        let server = self.settings.xmpp_server.clone();
        let port = self.settings.xmpp_port.clone();
        let account = self.settings.xmpp_account.clone();
        let resource = self.settings.xmpp_resource.clone();
        let password = self.xmpp_password.clone();
        let tx = self.result_tx.clone();
        self.status = format!("Тест XMPP: отправка сообщения на {recipient}...");
        thread::spawn(move || {
            let result = send_xmpp_message_blocking(
                &server,
                &port,
                &account,
                &resource,
                &password,
                &recipient,
                "ОЗ: тестовое сообщение XMPP, ответ не требуется.",
            );
            let message = match result {
                Ok(()) => format!("OZ_FOCUS\nТест XMPP успешно отправлен на {recipient}."),
                Err(error) => format!("Тест XMPP не пройден: {error}"),
            };
            let _ = tx.send(message);
        });
    }

    fn start_report(&mut self) {
        let date = self.settings.report_date.trim().to_owned();
        let period = self.settings.report_period.trim().to_owned();
        if let Err(error) = validate_report_date(&date) {
            self.status = format!("Отчет не сформирован: {error}");
            return;
        }
        if period != "day" && period != "week" {
            self.status = "Отчет не сформирован: период должен быть day или week".to_owned();
            return;
        }
        let settings = self.settings.clone();
        let password = self.mssql_password.clone();
        let tx = self.result_tx.clone();
        self.status = "Формирование отчета...".to_owned();
        thread::spawn(move || {
            let mut command = std::process::Command::new(
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("oz.exe")),
            );
            command.args([
                "report",
                "--period",
                &period,
                "--date",
                &date,
                "--config",
                &settings.config_path,
            ]);
            command.env(
                "MSSQL_CONNECTION_STRING",
                build_connection_string(&settings, &password),
            );
            let message = match command.output() {
                Ok(output) if output.status.success() => {
                    String::from_utf8_lossy(&output.stdout).into_owned()
                }
                Ok(output) => format!(
                    "Ошибка отчета ({}):\n{}{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
                Err(error) => format!("Не удалось запустить отчет: {error}"),
            };
            let _ = tx.send(message);
        });
    }
}

impl Drop for GuiApp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn run_gui_poll(
    settings: &GuiSettings,
    config_path: &str,
    mssql_password: &str,
    xmpp_password: &str,
    notified_fingerprint: &mut String,
) -> String {
    // GUI запускает тот же process-requests, что и CLI, поэтому ручная проверка
    // и фоновый опрос используют один и тот же код получения данных.
    let mut command = std::process::Command::new(
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("oz.exe")),
    );
    command.args(["process-requests", "--config", config_path]);
    command.env(
        "MSSQL_CONNECTION_STRING",
        build_connection_string(settings, mssql_password),
    );

    let output = match command.output() {
        Ok(output) => output,
        Err(error) => return format!("Не удалось запустить обработчик: {error:#}"),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let result = stdout
        .lines()
        .find(|line| line.starts_with("OZ_RESULT "))
        .and_then(parse_poll_result);

    let mut message = if output.status.success() {
        format!("Проверка завершена.\n{}{}", stdout, stderr)
    } else {
        format!("Ошибка ({}).\n{}{}", output.status, stdout, stderr)
    };

    // Уведомление отправляется только при изменении набора необработанных заявок.
    // Поэтому один и тот же запрос не создает поток сообщений каждую минуту.
    if let Some((pending, fingerprint)) = result {
        if pending == 0 {
            notified_fingerprint.clear();
        } else if fingerprint != *notified_fingerprint {
            if settings.xmpp_recipient.trim().is_empty() {
                *notified_fingerprint = fingerprint.clone();
                message = format!(
                    "OZ_FOCUS\nНайдено необработанных заявок: {pending}. Укажите JID получателя XMPP.\n{message}"
                );
            } else if xmpp_password.is_empty() {
                *notified_fingerprint = fingerprint.clone();
                message = format!(
                    "OZ_FOCUS\nНайдено необработанных заявок: {pending}. Укажите пароль XMPP.\n{message}"
                );
            } else {
                let body = format!(
                    "ОЗ: обнаружено необработанных заявок: {pending}. Требуется проверка в приложении."
                );
                let xmpp_result = std::thread::Builder::new()
                    .name("oz-xmpp".to_owned())
                    .spawn({
                        let server = settings.xmpp_server.clone();
                        let port = settings.xmpp_port.clone();
                        let account = settings.xmpp_account.clone();
                        let resource = settings.xmpp_resource.clone();
                        let recipient = settings.xmpp_recipient.clone();
                        let password = xmpp_password.to_owned();
                        move || {
                            send_xmpp_message_blocking(
                                &server, &port, &account, &resource, &password, &recipient, &body,
                            )
                        }
                    })
                    .map_err(|error| error.to_string())
                    .and_then(|handle| {
                        handle
                            .join()
                            .map_err(|_| "XMPP thread panicked".to_owned())
                            .and_then(|result| result)
                    });
                match xmpp_result {
                    Ok(()) => {
                        *notified_fingerprint = fingerprint;
                        message = format!(
                            "OZ_FOCUS\nОтправлено уведомление в Miranda. Необработанных заявок: {pending}.\n{message}"
                        );
                    }
                    Err(error) => {
                        *notified_fingerprint = fingerprint.clone();
                        message = format!(
                            "OZ_FOCUS\nНе удалось отправить XMPP-уведомление: {error}\n{message}"
                        );
                    }
                }
            }
        }
    }
    message
}

fn parse_poll_result(line: &str) -> Option<(usize, String)> {
    let mut pending = None;
    let mut fingerprint = None;
    for item in line.split_whitespace().skip(1) {
        let (key, value) = item.split_once('=')?;
        match key {
            "pending" => pending = value.parse().ok(),
            "fingerprint" => fingerprint = Some(value.to_owned()),
            _ => {}
        }
    }
    Some((pending?, fingerprint?))
}

// Блокирующая обертка нужна GUI-потоку: внутри создается короткоживущий Tokio
// runtime, а egui остается синхронным и простым.
fn send_xmpp_message_blocking(
    server: &str,
    port: &str,
    account: &str,
    resource: &str,
    password: &str,
    recipient: &str,
    body: &str,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| error.to_string())?;
    runtime
        .block_on(send_xmpp_message(
            server, port, account, resource, password, recipient, body,
        ))
        .map_err(|error| format!("{error:#}"))
}

// ATS ожидает обычное Miranda-сообщение "Позвонить <цель>" на JID pbx.
// Номер-источник определяется на АТС по XMPP-ресурсу рабочей станции через sippeers.
fn send_xmpp_call_blocking(
    server: &str,
    port: &str,
    account: &str,
    resource: &str,
    password: &str,
    recipient: &str,
    target: &str,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| error.to_string())?;
    runtime
        .block_on(send_xmpp_message(
            server,
            port,
            account,
            resource,
            password,
            recipient,
            &format!("Позвонить {target}"),
        ))
        .map_err(|error| format!("{error:#}"))
}

// Проверяем только техническую корректность цели. Разрешение номера, WS или
// JID выполняется штатным parser-ом ATS, поэтому OZ не дублирует его правила.
fn validate_call_target(target: &str) -> Result<()> {
    if target.is_empty() {
        bail!("цель звонка не указана")
    }
    if target.len() > 128 || target.chars().any(char::is_control) {
        bail!("недопустимая цель звонка")
    }
    Ok(())
}

async fn send_xmpp_message(
    server: &str,
    port: &str,
    account: &str,
    resource: &str,
    password: &str,
    recipient: &str,
    body: &str,
) -> Result<()> {
    // Реализация соответствует текущему ATS-контру: TCP XMPP, SASL PLAIN,
    // bind ресурса и одно chat-сообщение. TLS здесь не добавляем, поскольку
    // существующая ATS-схема работает внутри доверенного контура без TLS.
    let (localpart, domain) = account
        .split_once('@')
        .context("XMPP account must be a full JID")?;
    let port: u16 = port.parse().context("invalid XMPP port")?;
    validate_xmpp_resource(resource)?;
    let mut stream = TcpStream::connect((server, port))
        .await
        .with_context(|| format!("connect XMPP {server}:{port}"))?;
    let stream_open = format!(
        "<stream:stream to='{domain}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    );
    stream.write_all(stream_open.as_bytes()).await?;
    read_xmpp_until(&mut stream, "<stream:features", "XMPP features").await?;
    // SASL PLAIN содержит пароль только в памяти и в защищенном TCP-сеансе
    // внутреннего контура; в логи это значение никогда не выводится.
    let auth =
        base64::engine::general_purpose::STANDARD.encode(format!("\0{localpart}\0{password}"));
    stream
        .write_all(
            format!(
                "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth}</auth>"
            )
            .as_bytes(),
        )
        .await?;
    read_xmpp_until(&mut stream, "<success", "XMPP authentication").await?;
    stream.write_all(stream_open.as_bytes()).await?;
    read_xmpp_until(&mut stream, "<stream:features", "XMPP bind features").await?;
    let resource = xml_escape(resource);
    stream
        .write_all(
            format!(
                "<iq id='oz-bind-1' type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>"
            )
            .as_bytes(),
        )
        .await?;
    read_xmpp_until(&mut stream, "oz-bind-1", "XMPP resource binding").await?;
    let id = xml_escape(&format!("oz-{}", std::process::id()));
    let recipient = xml_escape(recipient);
    let body = xml_escape(body);
    stream
        .write_all(
            format!(
                "<message id='{id}' to='{recipient}' type='chat'><body>{body}</body></message>"
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(b"</stream:stream>").await?;
    Ok(())
}

// Ресурс XMPP используется АТС как имя рабочей станции для выбора номера.
fn validate_xmpp_resource(resource: &str) -> Result<()> {
    if resource.is_empty() || resource.len() > 64 {
        bail!("XMPP-ресурс должен содержать от 1 до 64 символов")
    }
    if resource.chars().any(|ch| {
        ch.is_control() || (!ch.is_ascii_alphanumeric() && !matches!(ch, '.' | '_' | '-'))
    }) {
        bail!("XMPP-ресурс содержит недопустимые символы")
    }
    Ok(())
}

async fn read_xmpp_until(stream: &mut TcpStream, marker: &str, context: &str) -> Result<()> {
    // Ограничение буфера защищает фоновый поток от бесконечного роста при
    // поврежденном или неожиданно большом ответе XMPP-сервера.
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut chunk))
            .await
            .with_context(|| format!("timeout during {context}"))??;
        if read == 0 {
            bail!("XMPP connection closed during {context}");
        }
        buffer.extend_from_slice(&chunk[..read]);
        let response = String::from_utf8_lossy(&buffer);
        if response.contains("<failure") || response.contains("<stream:error") {
            bail!("XMPP server returned an error during {context}");
        }
        if response.contains(marker) {
            return Ok(());
        }
        if buffer.len() > 128 * 1024 {
            bail!("XMPP response is too large during {context}");
        }
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

impl eframe::App for GuiApp {
    // egui вызывает update часто. Здесь только читаем сообщения из канала,
    // обновляем статус и рисуем форму; тяжелые операции выполняются в потоках.
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        if let Ok(message) = self.result_rx.try_recv() {
            if message.starts_with("OZ_FOCUS\nВиртуальный SIP-телефон") {
                self.sip_ready = true;
            } else if message.starts_with("SIP-регистрация не выполнена:") {
                self.sip_running = false;
                self.sip_ready = false;
            }
            if !self.settings.poll_enabled {
                self.running = false;
            }
            if let Some(message) = message.strip_prefix("OZ_FOCUS\n") {
                ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Focus);
                self.status = message.to_owned();
            } else {
                self.status = message;
            }
        }
        ctx.request_repaint_after(Duration::from_millis(250));
        eframe::egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("ОЗ — отслеживание заявок");
            ui.label("Подключения, параметры обработки и журнал запуска");
            ui.separator();
            eframe::egui::CollapsingHeader::new("MSSQL")
                .default_open(true)
                .show(ui, |ui| {
                    text_field(ui, "Сервер", &mut self.settings.sql_server);
                    text_field(ui, "Порт", &mut self.settings.sql_port);
                    text_field(ui, "База", &mut self.settings.sql_database);
                    text_field(ui, "Пользователь", &mut self.settings.sql_user);
                    password_field(ui, "Пароль", &mut self.mssql_password);
                });
            eframe::egui::CollapsingHeader::new("Фоновый опрос и Miranda/XMPP")
                .default_open(true)
                .show(ui, |ui| {
                    ui.checkbox(&mut self.settings.poll_enabled, "Включить фоновый опрос");
                    text_field(
                        ui,
                        "Интервал, секунд",
                        &mut self.settings.poll_interval_seconds,
                    );
                    text_field(ui, "XMPP-сервер", &mut self.settings.xmpp_server);
                    text_field(ui, "Порт XMPP", &mut self.settings.xmpp_port);
                    text_field(ui, "JID учетной записи", &mut self.settings.xmpp_account);
                    text_field(
                        ui,
                        "XMPP-ресурс (рабочая станция)",
                        &mut self.settings.xmpp_resource,
                    );
                    text_field(ui, "JID получателя", &mut self.settings.xmpp_recipient);
                    text_field(
                        ui,
                        "JID АТС для звонка",
                        &mut self.settings.xmpp_call_recipient,
                    );
                    password_field(ui, "Пароль XMPP", &mut self.xmpp_password);
                    ui.label(format!(
                        "Источник click-to-call: ресурс {} (номер выбирает АТС)",
                        self.settings.xmpp_resource
                    ));
                    text_field(
                        ui,
                        "Цель звонка (номер/WS/JID)",
                        &mut self.settings.call_target,
                    );
                    if ui
                        .add_enabled(
                            !self.settings.call_target.trim().is_empty()
                                && !self.xmpp_password.is_empty(),
                            eframe::egui::Button::new("Позвонить"),
                        )
                        .clicked()
                    {
                        self.start_call();
                    }
                    if ui
                        .add_enabled(
                            !self.settings.call_target.trim().is_empty()
                                && !self.xmpp_password.is_empty(),
                            eframe::egui::Button::new("Тест дозвона"),
                        )
                        .clicked()
                    {
                        self.start_call();
                    }
                    if ui
                        .add_enabled(
                            !self.settings.xmpp_recipient.trim().is_empty()
                                && !self.xmpp_password.is_empty(),
                            eframe::egui::Button::new("Тест XMPP"),
                        )
                        .clicked()
                    {
                        self.start_xmpp_test();
                    }
                    ui.label("Уведомление отправляется один раз для каждого нового набора заявок.");
                });
            eframe::egui::CollapsingHeader::new("Виртуальный SIP-телефон")
                .default_open(true)
                .show(ui, |ui| {
                    ui.checkbox(
                        &mut self.settings.sip_enabled,
                        "Включить виртуальный телефон",
                    );
                    text_field(ui, "SIP-сервер АТС", &mut self.settings.sip_server);
                    text_field(ui, "Порт SIP", &mut self.settings.sip_port);
                    text_field(ui, "SIP-номер", &mut self.settings.sip_username);
                    password_field(ui, "SIP Secret", &mut self.sip_password);
                    ui.label("Автоответ включен; используется кодек G.711 A-law (PCMA).");
                    if ui
                        .add_enabled(
                            self.settings.sip_enabled && !self.sip_password.is_empty(),
                            eframe::egui::Button::new("Подключить SIP"),
                        )
                        .clicked()
                    {
                        self.start_virtual_sip();
                    }
                    if ui
                        .add_enabled(self.sip_running, eframe::egui::Button::new("Отключить SIP"))
                        .clicked()
                    {
                        self.sip_stop.store(true, Ordering::Relaxed);
                        self.sip_running = false;
                        self.sip_ready = false;
                        self.status = "Остановка виртуального SIP-телефона...".to_owned();
                    }
                });
            ui.checkbox(
                &mut self.remember_secrets,
                "Хранить пароли в Credential Manager",
            );
            if ui.button("Сохранить настройки").clicked()
                && let Err(error) = self.save_settings()
            {
                self.status = format!("Ошибка сохранения: {error:#}");
            }
            eframe::egui::CollapsingHeader::new("Файлы и параметры")
                .default_open(true)
                .show(ui, |ui| {
                    text_field(ui, "Конфигурация", &mut self.settings.config_path);
                    text_field(ui, "SQL запрос", &mut self.settings.query_file);
                    text_field(ui, "Журнал SQLite", &mut self.settings.audit_db_path);
                });
            eframe::egui::CollapsingHeader::new("Отчет за период")
                .default_open(true)
                .show(ui, |ui| {
                    text_field(ui, "Опорная дата", &mut self.settings.report_date);
                    eframe::egui::ComboBox::from_label("Период")
                        .selected_text(&self.settings.report_period)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.settings.report_period,
                                "day".to_owned(),
                                "День",
                            );
                            ui.selectable_value(
                                &mut self.settings.report_period,
                                "week".to_owned(),
                                "Неделя",
                            );
                        });
                    if ui.button("Сформировать отчет").clicked() {
                        self.start_report();
                    }
                });
            ui.separator();
            if ui
                .add_enabled(!self.running, eframe::egui::Button::new("Запустить опрос"))
                .clicked()
            {
                self.start();
            }
            if ui
                .add_enabled(self.running, eframe::egui::Button::new("Остановить опрос"))
                .clicked()
            {
                self.stop.store(true, Ordering::Relaxed);
                self.sip_stop.store(true, Ordering::Relaxed);
                self.running = false;
                self.sip_running = false;
                self.sip_ready = false;
                self.status = "Остановка фонового опроса...".to_owned();
            }
            ui.separator();
            ui.label("Статус");
            eframe::egui::ScrollArea::vertical()
                .max_height(180.0)
                .show(ui, |ui| {
                    ui.monospace(&self.status);
                });
        });
    }
}

fn text_field(ui: &mut eframe::egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.text_edit_singleline(value);
    });
}

fn password_field(ui: &mut eframe::egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(eframe::egui::TextEdit::singleline(value).password(true));
    });
}

fn gui_settings_path() -> PathBuf {
    PathBuf::from("gui-settings.toml")
}

fn load_gui_settings() -> Result<GuiSettings> {
    let raw = fs::read_to_string(gui_settings_path()).context("read GUI settings")?;
    toml::from_str(&raw).context("parse GUI settings")
}

fn save_gui_settings(settings: &GuiSettings) -> Result<()> {
    fs::write(gui_settings_path(), toml::to_string_pretty(settings)?).context("write GUI settings")
}

fn secret_entry(name: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(GUI_SERVICE, name).context("create credential entry")
}

fn read_secret(name: &str) -> Result<String> {
    secret_entry(name)?
        .get_password()
        .context("read credential")
}

fn save_secret(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    secret_entry(name)?
        .set_password(value)
        .context("save credential")
}

fn build_connection_string(settings: &GuiSettings, password: &str) -> String {
    let auth = if settings.sql_user.trim().is_empty() {
        "Integrated Security=true".to_owned()
    } else {
        format!("user id={};password={}", settings.sql_user, password)
    };
    format!(
        "server=tcp:{},{};database={};{};TrustServerCertificate=true",
        settings.sql_server, settings.sql_port, settings.sql_database, auth
    )
}

// Генерируем минимальный runtime config для дочернего process-requests.
// Пароль MSSQL передается ему только через environment.
fn write_runtime_config(settings: &GuiSettings) -> Result<()> {
    let interval_seconds = settings
        .poll_interval_seconds
        .parse::<u64>()
        .unwrap_or(60)
        .max(5);
    let config = format!(
        r#"[runtime]
interval_seconds = {}
audit_db_path = {:?}

[mssql]
connection_string_env = "MSSQL_CONNECTION_STRING"
default_connection_string = "server=tcp:{},{};database={};TrustServerCertificate=true"
query_file = "{}"

[requests]
query_file = {:?}
mark_unapproved_as_seen = false
"#,
        interval_seconds,
        settings.audit_db_path,
        settings.sql_server,
        settings.sql_port,
        settings.sql_database,
        settings.query_file,
        settings.query_file
    );
    fs::write(&settings.config_path, config)
        .with_context(|| format!("write {}", settings.config_path))
}

fn run_gui() -> Result<()> {
    // У Windows включен windows_subsystem = "windows", поэтому запуск GUI не
    // открывает дополнительное консольное окно.
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "ОЗ — отслеживание заявок",
        options,
        Box::new(|_cc| {
            let mut app = GuiApp::new();
            if app.settings.poll_enabled {
                app.start();
            }
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| anyhow::anyhow!("GUI failed: {error}"))
}

fn load_config(path: &str) -> Result<AppConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
    toml::from_str(&raw).with_context(|| format!("parse config {path}"))
}

// Обработка заявок получает свежие данные, исключает уже просмотренные записи
// и сообщает о состоянии согласования. Изменение внешних систем временно не
// выполняется: этот режим оставляет заявки доступными для дальнейшей обработки.
async fn process_requests(config: &AppConfig) -> Result<()> {
    let requests_config = config
        .requests
        .as_ref()
        .context("requests section is required for process-requests")?;
    let audit = Audit::open(&config.runtime.audit_db_path)?;
    let query = fs::read_to_string(&requests_config.query_file)
        .with_context(|| format!("read request query file {}", requests_config.query_file))?;
    let requests = fetch_remote_work_requests(&config.mssql, &query).await?;

    info!(count = requests.len(), "fetched remote work requests");
    let mut pending_requests = Vec::new();
    for request in &requests {
        if !audit.is_request_processed(&request.request_num)? {
            pending_requests.push(request);
        }
    }
    // Отпечаток набора используется GUI для подавления повторных уведомлений.
    let pending_fingerprint = pending_requests
        .iter()
        .map(|request| request.request_num.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    println!(
        "OZ_RESULT fetched={} pending={} fingerprint={}",
        requests.len(),
        pending_requests.len(),
        hash_pending_requests(&pending_fingerprint)
    );

    for request in requests {
        if audit.is_request_processed(&request.request_num)? {
            info!(
                request_num = request.request_num,
                "request already processed"
            );
            continue;
        }

        // Наличие неисполненного поручения означает, что согласование не готово.
        // По умолчанию такая заявка остается видимой для следующего опроса.
        if request.por_neisp != 0 {
            warn!(
                request_num = request.request_num,
                requester = request.requester,
                por_neisp = request.por_neisp,
                "request approval is incomplete"
            );
            if requests_config.mark_unapproved_as_seen {
                audit.record_request_skipped(&request, "approval_incomplete")?;
            }
            continue;
        }

        info!(
            request_num = request.request_num,
            requester = request.requester,
            "approved request is ready for operator processing"
        );
    }

    Ok(())
}

// Отчет намеренно выводит только номера и технические статусы. ФИО, причины
// удаленной работы и другие поля заявки в консольный результат не попадают.
async fn report_requests(config: &AppConfig, period: ReportPeriod, date: &str) -> Result<()> {
    validate_report_date(date)?;
    let requests_config = config
        .requests
        .as_ref()
        .context("requests section is required for report")?;
    let source_query = fs::read_to_string(&requests_config.query_file)
        .with_context(|| format!("read request query file {}", requests_config.query_file))?;
    let query = query_for_report_period(&source_query, period, date)?;
    let requests = fetch_remote_work_requests(&config.mssql, &query).await?;

    let mut processed = 0usize;
    let mut waiting = 0usize;
    let mut rows = Vec::with_capacity(requests.len());
    for request in requests {
        // Источник истины для исполнения — por_neisp из MSSQL. Локальный
        // аудит не подменяет этот статус и нужен для повторных запусков OZ.
        let status = if request.por_neisp == 0 {
            processed += 1;
            "processed"
        } else {
            waiting += 1;
            "waiting"
        };
        rows.push((request.request_num, status));
    }

    println!(
        "OZ_REPORT period={} anchor_date={} total={} processed={} waiting={}",
        match period {
            ReportPeriod::Day => "day",
            ReportPeriod::Week => "week",
        },
        date,
        rows.len(),
        processed,
        waiting
    );
    for (number, status) in rows {
        println!("OZ_REQUEST num={} status={status}", number);
    }
    Ok(())
}

fn validate_report_date(date: &str) -> Result<()> {
    let valid = date.len() == 10
        && date.as_bytes()[4] == b'-'
        && date.as_bytes()[7] == b'-'
        && date
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit());
    if !valid {
        bail!("date must have YYYY-MM-DD format")
    }
    Ok(())
}

fn query_for_report_period(query: &str, period: ReportPeriod, date: &str) -> Result<String> {
    let end = format!("set @d2 = '{date}';");
    let start = match period {
        ReportPeriod::Day => format!("set @d1 = '{date}';"),
        // Rolling seven calendar days ending on the requested date.
        ReportPeriod::Week => format!("set @d1 = dateadd(day, -6, '{date}');"),
    };
    let mut replaced_start = false;
    let mut replaced_end = false;
    let mut lines = Vec::new();
    for line in query.lines() {
        let trimmed = line.trim_start().to_ascii_lowercase();
        if trimmed.starts_with("set @d1") {
            lines.push(start.clone());
            replaced_start = true;
        } else if trimmed.starts_with("set @d2") {
            lines.push(end.clone());
            replaced_end = true;
        } else {
            lines.push(line.to_owned());
        }
    }
    if !replaced_start || !replaced_end {
        bail!("request query must define @d1 and @d2")
    }
    Ok(lines.join("\n"))
}

async fn fetch_remote_work_requests(
    config: &SqlConfig,
    query: &str,
) -> Result<Vec<RemoteWorkRequest>> {
    // Запрос заявок хранится отдельным SQL-файлом, чтобы его можно было менять
    // без перекомпиляции Rust-приложения.
    let connection_string = config.connection_string()?;
    let mssql = MssqlConfig::from_ado_string(&connection_string)
        .with_context(|| format!("parse {}", config.connection_string_env))?;

    let tcp = TcpStream::connect(mssql.get_addr())
        .await
        .context("connect MSSQL")?;
    tcp.set_nodelay(true).context("set MSSQL TCP_NODELAY")?;

    let mut client = MssqlClient::connect(mssql, tcp.compat_write())
        .await
        .context("login MSSQL")?;

    let rows = client
        .simple_query(query)
        .await
        .context("execute MSSQL remote-work query")?
        .into_results()
        .await
        .context("read MSSQL request rows")?;

    let mut requests = Vec::new();
    for result_set in rows {
        for row in result_set {
            requests.push(remote_work_request_from_row(row)?);
        }
    }

    Ok(requests)
}

impl SqlConfig {
    // Сначала используем переменную окружения. Резервное значение из TOML
    // оставлено для совместимости, но секреты в обычный GUI-файл не попадают.
    fn connection_string(&self) -> Result<String> {
        match std::env::var(&self.connection_string_env) {
            Ok(value) => Ok(value),
            Err(_) => self
                .default_connection_string
                .clone()
                .with_context(|| format!("{} is required", self.connection_string_env)),
        }
    }
}

fn remote_work_request_from_row(row: tiberius::Row) -> Result<RemoteWorkRequest> {
    Ok(RemoteWorkRequest {
        request_num: get_required_str(&row, "num1")?,
        requester: get_required_str(&row, "ot_kogo")?,
        por_neisp: row.get::<i32, _>("por_neisp").unwrap_or(1),
    })
}

fn get_required_str(row: &tiberius::Row, name: &str) -> Result<String> {
    get_optional_str(row, name)
        .with_context(|| format!("required MSSQL column {name} is null or missing"))
}

fn get_optional_str(row: &tiberius::Row, name: &str) -> Option<String> {
    row.get::<&str, _>(name).map(str::to_owned)
}

fn hash_pending_requests(request_numbers: &str) -> String {
    // Отпечаток списка нужен GUI только для подавления повторных уведомлений.
    let mut hasher = Sha256::new();
    hasher.update(request_numbers.as_bytes());
    format!("{:x}", hasher.finalize())
}

struct Audit {
    conn: Connection,
}

impl Audit {
    // SQLite-аудит делает повторные запуски идемпотентными и сохраняет историю
    // уже просмотренных заявок.
    fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open audit DB {path}"))?;
        conn.execute_batch(
            "create table if not exists processed_requests (
                request_num text primary key,
                requester text not null,
                rule_key text,
                status text not null,
                processed_at text not null default current_timestamp
            );",
        )
        .context("migrate audit DB")?;
        Ok(Self { conn })
    }

    fn is_request_processed(&self, request_num: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "select count(*) from processed_requests where request_num = ?1",
            params![request_num],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn record_request_skipped(&self, request: &RemoteWorkRequest, status: &str) -> Result<()> {
        self.conn.execute(
            "insert or replace into processed_requests (request_num, requester, rule_key, status) values (?1, ?2, null, ?3)",
            params![request.request_num, request.requester, status],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_hash_is_stable() {
        let left = hash_pending_requests("42\n43");
        let right = hash_pending_requests("42\n43");

        assert_eq!(left, right);
    }

    #[test]
    fn poll_result_is_parsed() {
        let result = parse_poll_result("OZ_RESULT fetched=4 pending=2 fingerprint=abc123");
        assert_eq!(result, Some((2, "abc123".to_owned())));
    }

    #[test]
    fn report_query_uses_requested_day() {
        let query = "set @d1 = '20260801';\nset @d2 = '20260825';\nselect 1;";
        let actual = query_for_report_period(query, ReportPeriod::Day, "2026-09-01").unwrap();
        assert!(actual.contains("set @d1 = '2026-09-01';"));
        assert!(actual.contains("set @d2 = '2026-09-01';"));
    }

    #[test]
    fn report_query_uses_seven_day_window() {
        let query = "set @d1 = '20260801';\nset @d2 = '20260825';";
        let actual = query_for_report_period(query, ReportPeriod::Week, "2026-09-01").unwrap();
        assert!(actual.contains("dateadd(day, -6, '2026-09-01')"));
        assert!(actual.contains("set @d2 = '2026-09-01';"));
    }

    #[test]
    fn report_date_format_is_checked() {
        assert!(validate_report_date("2026-09-01").is_ok());
        assert!(validate_report_date("20260901").is_err());
    }

    #[test]
    fn xmpp_values_are_escaped() {
        assert_eq!(xml_escape("a<&\"'"), "a&lt;&amp;&quot;&apos;");
    }

    #[test]
    fn call_target_validation_rejects_control_chars_and_empty_values() {
        assert!(validate_call_target("").is_err());
        assert!(validate_call_target("WS-GST01\n").is_err());
        assert!(validate_call_target("135").is_ok());
    }

    #[test]
    fn gui_runtime_config_is_valid_toml_without_secrets() {
        let mut settings = GuiSettings::default();
        let path = std::env::temp_dir().join(format!("oz-test-{}.toml", std::process::id()));
        settings.config_path = path.to_string_lossy().into_owned();
        write_runtime_config(&settings).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        let config: AppConfig = toml::from_str(&raw).unwrap();
        let _ = fs::remove_file(path);
        assert_eq!(
            config.mssql.connection_string_env,
            "MSSQL_CONNECTION_STRING"
        );
        assert!(!raw.contains("password"));
    }
}
