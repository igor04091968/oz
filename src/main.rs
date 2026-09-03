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
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

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
    #[serde(default = "default_poll_lookback_days")]
    poll_lookback_days: u32,
}

fn default_poll_lookback_days() -> u32 {
    30
}

#[derive(Debug, Clone)]
struct RemoteWorkRequest {
    request_num: String,
    requester: String,
    por_neisp: i32,
}

const PFSENSE_CACHE_TTL_SECONDS: u64 = 3600;
const SIP_ANNOUNCEMENT_DELAY_SECONDS: u64 = 5;

fn write_sip_diagnostic(message: &str) {
    let path = std::env::temp_dir().join("oz-sip-media.log");
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{message}");
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PfsenseRuleCache {
    schema_version: u32,
    created_at: u64,
    interface: String,
    rules: Vec<PfsenseRuleGrant>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PfsenseRuleGrant {
    key: String,
    description: String,
    source: String,
    destination: String,
    schedule: String,
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
const PFSENSE_API_KEY: &str = "pfsense-api-key";

// Настройки GUI сериализуются в gui-settings.toml. Поля с паролями отсутствуют:
// реальные значения загружаются из Credential Manager только в память процесса.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct GuiSettings {
    config_path: String,
    poll_interval_seconds: String,
    poll_lookback_days: String,
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
    auto_call_on_pending: bool,
    sip_enabled: bool,
    sip_server: String,
    sip_port: String,
    sip_username: String,
    sip_audio_enabled: bool,
    sip_audio_file: String,
    report_date: String,
    report_period: String,
    pfsense_enabled: bool,
    pfsense_url: String,
    pfsense_timeout_seconds: String,
    pfsense_rules_interface: String,
    pfsense_ca_cert_path: String,
    pfsense_skip_tls_verify: bool,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            config_path: "config.toml".to_owned(),
            poll_interval_seconds: "60".to_owned(),
            poll_lookback_days: "30".to_owned(),
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
            xmpp_caller_extension: "1000".to_owned(),
            call_target: String::new(),
            auto_call_on_pending: true,
            sip_enabled: true,
            sip_server: "10.33.1.82".to_owned(),
            sip_port: "5060".to_owned(),
            sip_username: "1000".to_owned(),
            sip_audio_enabled: true,
            sip_audio_file: String::new(),
            report_date: "2026-09-01".to_owned(),
            report_period: "day".to_owned(),
            pfsense_enabled: false,
            pfsense_url: "https://10.35.0.1".to_owned(),
            pfsense_timeout_seconds: "60".to_owned(),
            pfsense_rules_interface: "openvpn".to_owned(),
            pfsense_ca_cert_path: String::new(),
            pfsense_skip_tls_verify: false,
        }
    }
}

struct GuiApp {
    settings: GuiSettings,
    mssql_password: String,
    xmpp_password: String,
    sip_password: String,
    pfsense_api_key: String,
    remember_secrets: bool,
    status: String,
    running: bool,
    stop: Arc<AtomicBool>,
    sip_stop: Arc<AtomicBool>,
    sip_running: bool,
    sip_ready: bool,
    announcement_text: Arc<Mutex<String>>,
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
        let pfsense_api_key = read_secret(PFSENSE_API_KEY).unwrap_or_default();
        let (result_tx, result_rx) = mpsc::channel();
        Self {
            settings,
            mssql_password,
            xmpp_password,
            sip_password,
            pfsense_api_key,
            remember_secrets: true,
            status: "Готово. Ожидание проверки заявок.".to_owned(),
            running: false,
            stop: Arc::new(AtomicBool::new(false)),
            sip_stop: Arc::new(AtomicBool::new(false)),
            sip_running: false,
            sip_ready: false,
            announcement_text: Arc::new(Mutex::new(
                "Количество заявок на удаленное подключение: 0.".to_owned(),
            )),
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
        let announcement_text = Arc::clone(&self.announcement_text);

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
                    &announcement_text,
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
            save_secret(PFSENSE_API_KEY, &self.pfsense_api_key)?;
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
        let audio_enabled = self.settings.sip_audio_enabled;
        let audio_file = self.settings.sip_audio_file.trim().to_owned();
        let announcement_text = Arc::clone(&self.announcement_text);
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
            let incoming_tx = tx.clone();
            phone.on_incoming(move |call| {
                // Callback регистрируется до автоответа: xphone вызовет его
                // после согласования SDP и готовности RTP-медиаканала.
                if audio_enabled {
                    let announcement = announcement_text
                        .lock()
                        .map(|value| value.clone())
                        .unwrap_or_else(|_| {
                            "Количество заявок на удаленное подключение: 0.".to_owned()
                        });
                    let audio_result = if audio_file.is_empty() || audio_file == "auto" {
                        synthesize_speech_wav(&announcement).and_then(|path| {
                            let result = load_pcm_wav(&path);
                            let _ = fs::remove_file(path);
                            result
                        })
                    } else {
                        load_pcm_wav(&audio_file)
                    };
                    match audio_result {
                        Ok(samples) => {
                            let frame_count = samples.len().div_ceil(160);
                            let prepared = format!(
                                "SIP_AUDIO_PREPARED samples={} frames={frame_count}",
                                samples.len()
                            );
                            write_sip_diagnostic(&prepared);
                            let _ = incoming_tx.send(prepared);
                            let weak_call = Arc::downgrade(&call);
                            let file_name = audio_file.clone();
                            let samples = Arc::new(samples);
                            let media_tx = incoming_tx.clone();
                            call.on_media(move || {
                                let weak_call = weak_call.clone();
                                let file_name = file_name.clone();
                                let samples = Arc::clone(&samples);
                                let media_tx = media_tx.clone();
                                write_sip_diagnostic("SIP_MEDIA_CALLBACK_FIRED");
                                let _ = media_tx.send("SIP_MEDIA_CALLBACK_FIRED".to_owned());
                                thread::spawn(move || {
                                    // АТС сначала отвечает на виртуальный номер 1000,
                                    // затем дозванивается до целевого абонента и только
                                    // после этого создает bridge. Немедленная передача
                                    // RTP попадает в первый leg и до абонента не доходит.
                                    thread::sleep(Duration::from_secs(
                                        SIP_ANNOUNCEMENT_DELAY_SECONDS,
                                    ));
                                    if let Some(call) = weak_call.upgrade()
                                        && let Some(writer) = call.pcm_writer()
                                    {
                                        write_sip_diagnostic("SIP_PCM_WRITER_ACQUIRED");
                                        let _ = media_tx.send("SIP_PCM_WRITER_ACQUIRED".to_owned());
                                        const PCMA_FRAME_SAMPLES: usize = 160;
                                        let mut sent_frames = 0usize;
                                        for chunk in samples.chunks(PCMA_FRAME_SAMPLES) {
                                            let mut frame = chunk.to_vec();
                                            frame.resize(PCMA_FRAME_SAMPLES, 0);
                                            if let Err(error) = writer.send(frame) {
                                                warn!(
                                                    file = %file_name,
                                                    error = %error,
                                                    frame = sent_frames,
                                                    "SIP voice message frame send failed"
                                                );
                                                break;
                                            }
                                            sent_frames += 1;
                                            thread::sleep(Duration::from_millis(20));
                                        }
                                        info!(
                                            file = %file_name,
                                            frames = sent_frames,
                                            delay_seconds = SIP_ANNOUNCEMENT_DELAY_SECONDS,
                                            "SIP voice message playback started"
                                        );
                                        let sent = format!(
                                            "SIP_RTP_FRAMES_SENT count={sent_frames}"
                                        );
                                        write_sip_diagnostic(&sent);
                                        let _ = media_tx.send(sent);
                                    } else {
                                        write_sip_diagnostic("SIP_PCM_WRITER_UNAVAILABLE");
                                        let _ = media_tx.send("SIP_PCM_WRITER_UNAVAILABLE".to_owned());
                                        warn!(
                                            file = %file_name,
                                            "SIP voice message playback skipped: call media is unavailable"
                                        );
                                    }
                                });
                            });
                        }
                        Err(error) => {
                            let diagnostic = format!("SIP_AUDIO_PREPARE_FAILED error={error:#}");
                            write_sip_diagnostic(&diagnostic);
                            let _ = incoming_tx.send(diagnostic);
                            warn!(file = %audio_file, error = %error, "SIP voice message unavailable");
                        }
                    }
                }
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

    fn start_pfsense_test(&mut self) {
        let base_url = self.settings.pfsense_url.trim().to_owned();
        let timeout = self
            .settings
            .pfsense_timeout_seconds
            .trim()
            .parse::<u64>()
            .unwrap_or(60)
            .clamp(5, 300);
        let api_key = self.pfsense_api_key.clone();
        let rules_interface = self.settings.pfsense_rules_interface.trim().to_owned();
        let ca_cert_path = self.settings.pfsense_ca_cert_path.trim().to_owned();
        let skip_tls_verify = self.settings.pfsense_skip_tls_verify;
        let tx = self.result_tx.clone();
        if !self.settings.pfsense_enabled {
            self.status = "pfSense API: включите интеграцию в настройках.".to_owned();
            return;
        }
        if api_key.trim().is_empty() {
            self.status =
                "pfSense API: укажите API-ключ; он сохранится только в Credential Manager."
                    .to_owned();
            return;
        }
        self.status = "Проверка pfSense REST API v2...".to_owned();
        thread::spawn(move || {
            let message = match PfsenseClient::new(
                &base_url,
                &api_key,
                timeout,
                &ca_cert_path,
                skip_tls_verify,
            )
            .and_then(|client| {
                let cache = client.fetch_rule_cache(&rules_interface)?;
                save_pfsense_rule_cache(&cache)?;
                Ok(format!(
                    "кэш разрешений обновлён: {} активных правил, интерфейс {}, TTL {} с",
                    cache.rules.len(),
                    cache.interface,
                    PFSENSE_CACHE_TTL_SECONDS
                ))
            }) {
                Ok(summary) => format!("OZ_FOCUS\npfSense REST API v2 доступен. {summary}"),
                Err(error) => format!("pfSense REST API v2: проверка не пройдена: {error:#}"),
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
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    format_quick_report(&stdout).unwrap_or_else(|| stdout.into_owned())
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
    announcement_text: &Arc<Mutex<String>>,
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
    let pending_numbers = parse_pending_numbers(&stdout);
    let pending_list = format_request_numbers(&pending_numbers);

    let mut message = if output.status.success() {
        format!("Проверка завершена.\n{}{}", stdout, stderr)
    } else {
        format!("Ошибка ({}).\n{}{}", output.status, stdout, stderr)
    };

    if settings.pfsense_enabled {
        match load_valid_pfsense_cache(&settings.pfsense_rules_interface) {
            Ok(cache) => message.push_str(&format!(
                "\nПроверка доступа по кэшу pfSense ({}):\n{}",
                cache.interface,
                format_access_report(&stdout, &cache)
            )),
            Err(error) => message.push_str(&format!(
                "\nДоступ по pfSense не проверен: кэш недоступен или устарел ({error})"
            )),
        }
    }

    // Уведомление отправляется только при изменении набора необработанных заявок.
    // Поэтому один и тот же запрос не создает поток сообщений каждую минуту.
    if let Some((pending, fingerprint)) = result {
        if let Ok(mut current) = announcement_text.lock() {
            *current = format_pending_announcement(pending, &pending_list);
        }
        if pending == 0 {
            notified_fingerprint.clear();
        } else if fingerprint != *notified_fingerprint {
            if settings.xmpp_recipient.trim().is_empty() {
                *notified_fingerprint = fingerprint.clone();
                message = format!(
                    "OZ_FOCUS\n{}. Укажите JID получателя XMPP.\n{message}",
                    format_pending_announcement(pending, &pending_list)
                );
            } else if xmpp_password.is_empty() {
                *notified_fingerprint = fingerprint.clone();
                message = format!(
                    "OZ_FOCUS\n{}. Укажите пароль XMPP.\n{message}",
                    format_pending_announcement(pending, &pending_list)
                );
            } else {
                let body = format!(
                    "ОЗ: {}. Требуется проверка в приложении.",
                    format_pending_announcement(pending, &pending_list)
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
                        let mut actions = format!(
                            "OZ_FOCUS\nОтправлено уведомление в Miranda. {}\n{message}",
                            format_pending_announcement(pending, &pending_list)
                        );
                        if settings.auto_call_on_pending {
                            let target = settings.call_target.trim();
                            if target.is_empty() {
                                actions
                                    .push_str("\nАвтодозвон не выполнен: не указана цель звонка.");
                            } else if let Err(error) = validate_call_target(target) {
                                actions.push_str(&format!("\nАвтодозвон не выполнен: {error}."));
                            } else {
                                let call_result = send_xmpp_call_blocking(
                                    &settings.xmpp_server,
                                    &settings.xmpp_port,
                                    &settings.xmpp_account,
                                    &settings.xmpp_resource,
                                    xmpp_password,
                                    &settings.xmpp_call_recipient,
                                    target,
                                );
                                match call_result {
                                    Ok(()) => actions
                                        .push_str(&format!("\nАвтодозвон отправлен на {target}.")),
                                    Err(error) => actions.push_str(&format!(
                                        "\nАвтодозвон не отправлен: {error:#}."
                                    )),
                                }
                            }
                        }
                        message = actions;
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

fn parse_pending_numbers(output: &str) -> Vec<String> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("OZ_PENDING_NUMS "))
        .map(|numbers| {
            numbers
                .split(',')
                .map(str::trim)
                .filter(|number| !number.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn format_request_numbers(numbers: &[String]) -> String {
    if numbers.is_empty() {
        "нет".to_owned()
    } else {
        numbers.join(", ")
    }
}

fn format_pending_announcement(pending: usize, numbers: &str) -> String {
    if pending == 0 {
        "Необработанных заявок нет".to_owned()
    } else {
        format!("Необработанных заявок - {pending} штук, номера: {numbers}")
    }
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

// Читаем только несжатый PCM WAV: файл можно подготовить заранее без
// внешнего медиасервера и без передачи текста сообщения облачному TTS.
fn load_pcm_wav(path: impl AsRef<std::path::Path>) -> Result<Vec<i16>> {
    let path = path.as_ref();
    let data =
        fs::read(path).with_context(|| format!("не удалось прочитать WAV: {}", path.display()))?;
    if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" {
        bail!("файл не является WAV RIFF");
    }
    let mut offset = 12usize;
    let mut channels = 0u16;
    let mut sample_rate = 0u32;
    let mut bits_per_sample = 0u16;
    let mut audio_format = 0u16;
    let mut pcm_data = None;
    while offset + 8 <= data.len() {
        let id = &data[offset..offset + 4];
        let size = u32::from_le_bytes(data[offset + 4..offset + 8].try_into()?) as usize;
        let start = offset + 8;
        let end = start.checked_add(size).context("поврежденный WAV chunk")?;
        if end > data.len() {
            bail!("WAV chunk выходит за пределы файла");
        }
        match id {
            b"fmt " if size >= 16 => {
                audio_format = u16::from_le_bytes(data[start..start + 2].try_into()?);
                channels = u16::from_le_bytes(data[start + 2..start + 4].try_into()?);
                sample_rate = u32::from_le_bytes(data[start + 4..start + 8].try_into()?);
                bits_per_sample = u16::from_le_bytes(data[start + 14..start + 16].try_into()?);
            }
            b"data" => pcm_data = Some(&data[start..end]),
            _ => {}
        }
        offset = end + (size % 2);
    }
    if audio_format != 1 || channels == 0 || sample_rate == 0 || bits_per_sample != 16 {
        bail!("требуется несжатый 16-битный PCM WAV");
    }
    let raw = pcm_data.context("в WAV отсутствует data chunk")?;
    if raw.len() % (channels as usize * 2) != 0 {
        bail!("размер PCM-данных не соответствует числу каналов");
    }
    let mut samples = Vec::with_capacity(raw.len() / (channels as usize * 2));
    for frame in raw.chunks_exact(channels as usize * 2) {
        let mut sum = 0i32;
        for channel in frame.chunks(2) {
            sum += i16::from_le_bytes(channel.try_into()?) as i32;
        }
        samples.push((sum / channels as i32) as i16);
    }
    if sample_rate != 8000 {
        samples = resample_pcm(&samples, sample_rate)?;
    }
    if samples.is_empty() {
        bail!("WAV не содержит сэмплов");
    }
    Ok(samples)
}

// Генерируем короткое объявление локальным Windows Speech API. Текст содержит
// только число заявок и служебную фразу, поэтому не уходит провайдеру TTS.
fn synthesize_speech_wav(text: &str) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let path =
            std::env::temp_dir().join(format!("oz-voice-{}-{stamp}.wav", std::process::id()));
        let encode = |value: &str| base64::engine::general_purpose::STANDARD.encode(value);
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                "Add-Type -AssemblyName System.Speech; $t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:OZ_TTS_TEXT)); $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:OZ_TTS_PATH)); $s=New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.SetOutputToWaveFile($p); $s.Speak($t); $s.Dispose()",
            ])
            .env("OZ_TTS_TEXT", encode(text))
            .env("OZ_TTS_PATH", encode(&path.to_string_lossy()))
            .output()
            .context("запуск локального Windows Speech API")?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            bail!("Windows Speech API завершился с ошибкой: {error}");
        }
        Ok(path)
    }
    #[cfg(not(windows))]
    {
        let _ = text;
        bail!("локальный TTS для динамического сообщения доступен в Windows-сборке")
    }
}

fn resample_pcm(samples: &[i16], input_rate: u32) -> Result<Vec<i16>> {
    if input_rate == 0 {
        bail!("некорректная частота дискретизации");
    }
    let output_len = ((samples.len() as u64 * 8000) / input_rate as u64) as usize;
    let mut output = Vec::with_capacity(output_len.max(1));
    for index in 0..output_len {
        let source = ((index as u64 * input_rate as u64) / 8000) as usize;
        output.push(samples[source.min(samples.len() - 1)]);
    }
    Ok(output)
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
        eframe::egui::TopBottomPanel::top("oz_top_panel").show(ctx, |ui| {
            eframe::egui::Frame::none()
                .fill(eframe::egui::Color32::from_rgb(0, 120, 212))
                .inner_margin(eframe::egui::Margin::same(14.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(
                            eframe::egui::RichText::new("ОЗ")
                                .color(eframe::egui::Color32::WHITE)
                                .strong(),
                        );
                        ui.label(
                            eframe::egui::RichText::new("Отслеживание заявок")
                                .color(eframe::egui::Color32::WHITE)
                                .size(18.0),
                        );
                    });
                });
            eframe::egui::menu::bar(ui, |ui| {
                ui.menu_button("Файл", |ui| {
                    ui.set_min_width(260.0);
                    if ui.button("Сохранить настройки").clicked() {
                        if let Err(error) = self.save_settings() {
                            self.status = format!("Ошибка сохранения: {error:#}");
                        }
                        ui.close_menu();
                    }
                    if ui.button("Закрыть").clicked() {
                        ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Подключения", |ui| {
                    ui.set_min_width(440.0);
                    ui.label(eframe::egui::RichText::new("MSSQL").strong());
                    text_field(ui, "Сервер", &mut self.settings.sql_server);
                    text_field(ui, "Порт", &mut self.settings.sql_port);
                    text_field(ui, "База", &mut self.settings.sql_database);
                    text_field(ui, "Пользователь", &mut self.settings.sql_user);
                    password_field(ui, "Пароль", &mut self.mssql_password);
                    ui.separator();
                    ui.label(eframe::egui::RichText::new("Miranda / XMPP").strong());
                    text_field(ui, "XMPP-сервер", &mut self.settings.xmpp_server);
                    text_field(ui, "Порт XMPP", &mut self.settings.xmpp_port);
                    text_field(ui, "JID учетной записи", &mut self.settings.xmpp_account);
                    text_field(ui, "XMPP-ресурс", &mut self.settings.xmpp_resource);
                    text_field(ui, "JID получателя", &mut self.settings.xmpp_recipient);
                    text_field(
                        ui,
                        "JID АТС для звонка",
                        &mut self.settings.xmpp_call_recipient,
                    );
                    password_field(ui, "Пароль XMPP", &mut self.xmpp_password);
                    ui.separator();
                    ui.label(eframe::egui::RichText::new("Виртуальный SIP-телефон").strong());
                    ui.checkbox(
                        &mut self.settings.sip_enabled,
                        "Включить виртуальный телефон",
                    );
                    text_field(ui, "SIP-сервер АТС", &mut self.settings.sip_server);
                    text_field(ui, "Порт SIP", &mut self.settings.sip_port);
                    text_field(ui, "SIP-номер", &mut self.settings.sip_username);
                    password_field(ui, "SIP Secret", &mut self.sip_password);
                    ui.checkbox(
                        &mut self.settings.sip_audio_enabled,
                        "Проигрывать голосовое сообщение",
                    );
                    text_field(ui, "Файл сообщения WAV", &mut self.settings.sip_audio_file);
                });
                ui.menu_button("pfSense", |ui| {
                    ui.set_min_width(440.0);
                    ui.label(eframe::egui::RichText::new("pfSense REST API v2").strong());
                    ui.checkbox(&mut self.settings.pfsense_enabled, "Включить интеграцию");
                    text_field(ui, "URL pfSense", &mut self.settings.pfsense_url);
                    text_field(
                        ui,
                        "Таймаут, секунд",
                        &mut self.settings.pfsense_timeout_seconds,
                    );
                    text_field(
                        ui,
                        "Интерфейс правил pfSense",
                        &mut self.settings.pfsense_rules_interface,
                    );
                    text_field(
                        ui,
                        "CA-сертификат pfSense",
                        &mut self.settings.pfsense_ca_cert_path,
                    );
                    ui.checkbox(
                        &mut self.settings.pfsense_skip_tls_verify,
                        "Пропустить проверку TLS-сертификата (только закрытая сеть)",
                    );
                    if self.settings.pfsense_skip_tls_verify {
                        ui.colored_label(
                            eframe::egui::Color32::RED,
                            "ВНИМАНИЕ: сертификат pfSense не проверяется.",
                        );
                    }
                    password_field(ui, "API-ключ", &mut self.pfsense_api_key);
                    if ui
                        .add_enabled(
                            self.settings.pfsense_enabled && !self.pfsense_api_key.is_empty(),
                            eframe::egui::Button::new("Обновить кэш разрешений"),
                        )
                        .clicked()
                    {
                        self.start_pfsense_test();
                        ui.close_menu();
                    }
                });
                ui.menu_button("Заявки", |ui| {
                    ui.set_min_width(440.0);
                    ui.label(eframe::egui::RichText::new("Фоновый опрос").strong());
                    ui.checkbox(&mut self.settings.poll_enabled, "Включить фоновый опрос");
                    text_field(
                        ui,
                        "Интервал, секунд",
                        &mut self.settings.poll_interval_seconds,
                    );
                    text_field(
                        ui,
                        "Глубина выборки, дней",
                        &mut self.settings.poll_lookback_days,
                    );
                    ui.separator();
                    ui.label(eframe::egui::RichText::new("Файлы и аудит").strong());
                    text_field(ui, "Конфигурация", &mut self.settings.config_path);
                    text_field(ui, "SQL-запрос", &mut self.settings.query_file);
                    text_field(ui, "Журнал SQLite", &mut self.settings.audit_db_path);
                    ui.checkbox(
                        &mut self.remember_secrets,
                        "Хранить пароли в Credential Manager",
                    );
                });
                ui.menu_button("Отчет", |ui| {
                    ui.set_min_width(360.0);
                    ui.label(eframe::egui::RichText::new("Параметры поиска").strong());
                    text_field(ui, "Дата заявки", &mut self.settings.report_date);
                    eframe::egui::ComboBox::from_label("Период")
                        .selected_text(report_period_label(&self.settings.report_period))
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
                        ui.close_menu();
                    }
                });
                ui.menu_button("Действия", |ui| {
                    ui.set_min_width(380.0);
                    ui.label(eframe::egui::RichText::new("Опрос и звонки").strong());
                    text_field(
                        ui,
                        "Цель звонка (номер/WS/JID)",
                        &mut self.settings.call_target,
                    );
                    ui.checkbox(
                        &mut self.settings.auto_call_on_pending,
                        "Автодозвон при новой заявке",
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
                    ui.separator();
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
                    ui.separator();
                    if ui
                        .add_enabled(
                            !self.running,
                            eframe::egui::Button::new("Запустить опрос")
                                .fill(eframe::egui::Color32::from_rgb(0, 120, 212)),
                        )
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
                });
            });
            eframe::egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(eframe::egui::RichText::new("Быстрый отчет").strong());
                    text_field(ui, "Дата", &mut self.settings.report_date);
                    eframe::egui::ComboBox::from_id_salt("quick_report_period")
                        .selected_text(report_period_label(&self.settings.report_period))
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
                    if ui.button("Сформировать").clicked() {
                        self.start_report();
                    }
                });
            });
        });
        eframe::egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Состояние OZ");
            ui.label("Результаты опроса базы данных и выполнения действий");
            ui.separator();
            eframe::egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    let state = if self.running {
                        "Опрос активен"
                    } else {
                        "Опрос остановлен"
                    };
                    ui.label(eframe::egui::RichText::new(state).strong());
                    ui.separator();
                    let sip_state = if self.sip_ready {
                        "SIP зарегистрирован"
                    } else {
                        "SIP не зарегистрирован"
                    };
                    ui.label(sip_state);
                });
            });
            ui.add_space(8.0);
            ui.label("Журнал");
            eframe::egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.monospace(&self.status);
                });
        });
    }
}

fn report_period_label(period: &str) -> &'static str {
    match period {
        "week" => "Неделя",
        _ => "День",
    }
}

fn format_quick_report(output: &str) -> Option<String> {
    let report_line = output.lines().find(|line| line.starts_with("OZ_REPORT "))?;
    let processed = report_line
        .split_whitespace()
        .find_map(|item| item.strip_prefix("processed=")?.parse::<usize>().ok())?;
    let mut entries = Vec::new();

    for line in output
        .lines()
        .filter(|line| line.starts_with("OZ_REQUEST "))
    {
        let Some(fields) = line.strip_prefix("OZ_REQUEST ") else {
            continue;
        };
        let Some((number, rest)) = fields.split_once(" requester=") else {
            continue;
        };
        let Some(requester) = rest.strip_suffix(" status=processed") else {
            continue;
        };
        let number = number.trim().strip_prefix("num=").unwrap_or(number.trim());
        if !number.is_empty() && !requester.trim().is_empty() {
            entries.push(format!("№ {number} — {}", requester.trim()));
        }
    }

    let mut report = format!("Быстрый отчет\nОбработано заявок: {processed}\n");
    if entries.is_empty() {
        report.push_str("Обработанные заявки: нет");
    } else {
        report.push_str("Обработанные заявки:\n");
        report.push_str(&entries.join("\n"));
    }
    Some(report)
}

fn format_access_report(output: &str, cache: &PfsenseRuleCache) -> String {
    let mut rows = Vec::new();
    for line in output
        .lines()
        .filter(|line| line.starts_with("OZ_ACCESS_REQUEST "))
    {
        let Some(fields) = line.strip_prefix("OZ_ACCESS_REQUEST ") else {
            continue;
        };
        let Some((number, rest)) = fields.split_once(" requester=") else {
            continue;
        };
        let Some((requester, status)) = rest.rsplit_once(" status=") else {
            continue;
        };
        let requester = requester.trim();
        let key = normalized_requester_key(requester);
        let matching_rule = key.as_deref().and_then(|key| {
            cache
                .rules
                .iter()
                .find(|rule| rule.key == key || rule.key.starts_with(&format!("{key}_")))
        });
        let access = match (status, matching_rule) {
            ("processed", Some(rule)) => format!(
                "доступ разрешён; правило {}; расписание {}",
                rule.description, rule.schedule
            ),
            ("processed", None) => "доступ запрещён: разрешающее правило не найдено".to_owned(),
            ("approved", _) => "заявка согласована, но ещё не обработана".to_owned(),
            _ => "заявка ожидает обработки".to_owned(),
        };
        rows.push(format!(
            "№ {} — {}: {}",
            number.trim().trim_start_matches("num="),
            requester,
            access
        ));
    }
    if rows.is_empty() {
        "Заявок в текущем SQL-окне нет.".to_owned()
    } else {
        rows.join("\n")
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

fn pfsense_cache_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("определение директории программы")?;
    Ok(executable
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("pfsense-rules-cache.json"))
}

fn save_pfsense_rule_cache(cache: &PfsenseRuleCache) -> Result<()> {
    let path = pfsense_cache_path()?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(cache)?)
        .with_context(|| format!("запись временного кэша pfSense {}", temporary.display()))?;
    fs::rename(&temporary, &path)
        .with_context(|| format!("атомарная замена кэша pfSense {}", path.display()))
}

fn load_valid_pfsense_cache(interface: &str) -> Result<PfsenseRuleCache> {
    let path = pfsense_cache_path()?;
    let raw = fs::read(&path).with_context(|| format!("чтение кэша pfSense {}", path.display()))?;
    let cache: PfsenseRuleCache = serde_json::from_slice(&raw).context("разбор кэша pfSense")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if cache.schema_version != 1 || cache.interface != interface {
        bail!("кэш pfSense не соответствует текущему интерфейсу или версии");
    }
    if now.saturating_sub(cache.created_at) > PFSENSE_CACHE_TTL_SECONDS {
        bail!(
            "кэш pfSense устарел (старше {} секунд)",
            PFSENSE_CACHE_TTL_SECONDS
        );
    }
    Ok(cache)
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
poll_lookback_days = {}

[pfsense]
base_url = {:?}
api_key_env = "OZ_PFSENSE_API_KEY"
timeout_seconds = {}
rules_interface = {:?}
ca_cert_path = {:?}
skip_tls_verify = {}
"#,
        interval_seconds,
        settings.audit_db_path,
        settings.sql_server,
        settings.sql_port,
        settings.sql_database,
        settings.query_file,
        settings.query_file,
        settings
            .poll_lookback_days
            .parse::<u32>()
            .unwrap_or(default_poll_lookback_days())
            .max(1),
        settings.pfsense_url,
        settings
            .pfsense_timeout_seconds
            .parse::<u64>()
            .unwrap_or(60)
            .clamp(5, 300),
        settings.pfsense_rules_interface,
        settings.pfsense_ca_cert_path,
        settings.pfsense_skip_tls_verify
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
        Box::new(|cc| {
            apply_microsoft_style(&cc.egui_ctx);
            let mut app = GuiApp::new();
            if app.settings.poll_enabled {
                app.start();
            }
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| anyhow::anyhow!("GUI failed: {error}"))
}

// Сдержанная светлая тема в духе стандартных приложений Windows: белая рабочая
// область, серые служебные поверхности и синий цвет системного акцента.
fn apply_microsoft_style(ctx: &eframe::egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = eframe::egui::vec2(8.0, 6.0);
    style.spacing.button_padding = eframe::egui::vec2(12.0, 6.0);
    style.spacing.interact_size.y = 28.0;

    let mut visuals = eframe::egui::Visuals::light();
    visuals.window_fill = eframe::egui::Color32::from_rgb(255, 255, 255);
    visuals.panel_fill = eframe::egui::Color32::from_rgb(250, 250, 250);
    visuals.faint_bg_color = eframe::egui::Color32::from_rgb(243, 243, 243);
    visuals.extreme_bg_color = eframe::egui::Color32::from_rgb(255, 255, 255);
    visuals.selection.bg_fill = eframe::egui::Color32::from_rgb(0, 120, 212);
    visuals.selection.stroke.color = eframe::egui::Color32::from_rgb(0, 90, 158);
    visuals.hyperlink_color = eframe::egui::Color32::from_rgb(0, 103, 192);
    visuals.widgets.inactive.bg_fill = eframe::egui::Color32::from_rgb(246, 246, 246);
    visuals.widgets.hovered.bg_fill = eframe::egui::Color32::from_rgb(232, 240, 254);
    visuals.widgets.active.bg_fill = eframe::egui::Color32::from_rgb(204, 228, 247);
    style.visuals = visuals;
    ctx.set_style(style);
}

fn load_config(path: &str) -> Result<AppConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
    toml::from_str(&raw).with_context(|| format!("parse config {path}"))
}

// Обработка заявок получает свежие данные, исключает уже обработанные записи
// и фиксирует согласованные заявки в локальном аудите. pfSense при этом не
// изменяется: доступ проверяется GUI по ранее сохраненному кэшу правил.
async fn process_requests(config: &AppConfig) -> Result<()> {
    let requests_config = config
        .requests
        .as_ref()
        .context("requests section is required for process-requests")?;
    let audit = Audit::open(&config.runtime.audit_db_path)?;
    let source_query = fs::read_to_string(&requests_config.query_file)
        .with_context(|| format!("read request query file {}", requests_config.query_file))?;
    let query = query_for_poll_lookback(&source_query, requests_config.poll_lookback_days)?;
    let requests = fetch_remote_work_requests(&config.mssql, &query).await?;

    info!(count = requests.len(), "fetched remote work requests");
    let mut pending_requests = Vec::new();
    for request in &requests {
        // Необработанной считаем именно заявку с неисполненным поручением.
        // por_neisp из MSSQL является источником истины для этого статуса.
        if request.por_neisp != 0 && !audit.is_request_processed(&request.request_num)? {
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
    println!(
        "OZ_PENDING_NUMS {}",
        pending_requests
            .iter()
            .map(|request| request.request_num.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    for request in &pending_requests {
        println!(
            "OZ_PENDING_REQUEST num={} requester={}",
            request.request_num, request.requester
        );
    }

    for request in &requests {
        let status = if audit.is_request_processed(&request.request_num)? {
            "processed"
        } else if request.por_neisp != 0 {
            "waiting"
        } else {
            audit.record_request_processed(request)?;
            "processed"
        };
        println!(
            "OZ_ACCESS_REQUEST num={} requester={} status={status}",
            request.request_num, request.requester
        );
    }

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

        audit.record_request_processed(&request)?;
        info!(
            request_num = request.request_num,
            requester = request.requester,
            "approved request processed by OZ"
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
        rows.push((request.request_num, request.requester, status));
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
    for (number, requester, status) in rows {
        println!(
            "OZ_REQUEST num={} requester={} status={status}",
            number, requester
        );
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

// Фоновый опрос использует скользящее окно, чтобы даты в SQL-файле не
// приходилось менять вручную. Граница периода вычисляется самим SQL Server.
fn query_for_poll_lookback(query: &str, lookback_days: u32) -> Result<String> {
    let days = lookback_days.max(1);
    let start = format!(
        "set @d1 = dateadd(day, -{}, cast(getdate() as date));",
        days.saturating_sub(1)
    );
    let end = "set @d2 = cast(getdate() as date);";
    let mut replaced_start = false;
    let mut replaced_end = false;
    let mut lines = Vec::new();
    for line in query.lines() {
        let trimmed = line.trim_start().to_ascii_lowercase();
        if trimmed.starts_with("set @d1") {
            lines.push(start.clone());
            replaced_start = true;
        } else if trimmed.starts_with("set @d2") {
            lines.push(end.to_owned());
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

// Read-only клиент pfSense API v2. Ключ передается в заголовке X-API-Key и
// никогда не включается в URL, сообщения журнала или текст ошибки.
struct PfsenseClient {
    client: reqwest::blocking::Client,
    base_url: String,
    api_key: String,
}

impl PfsenseClient {
    fn new(
        base_url: &str,
        api_key: &str,
        timeout_seconds: u64,
        ca_cert_path: &str,
        skip_tls_verify: bool,
    ) -> Result<Self> {
        let base_url = base_url.trim().trim_end_matches('/').to_owned();
        if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
            bail!("URL pfSense должен начинаться с http:// или https://");
        }
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds.clamp(5, 300)));
        if !ca_cert_path.trim().is_empty() {
            let certificate_bytes = fs::read(ca_cert_path)
                .with_context(|| format!("чтение CA-сертификата pfSense: {ca_cert_path}"))?;
            let certificate = if certificate_bytes
                .windows(b"-----BEGIN CERTIFICATE-----".len())
                .any(|window| window == b"-----BEGIN CERTIFICATE-----")
            {
                reqwest::Certificate::from_pem(&certificate_bytes)
            } else {
                reqwest::Certificate::from_der(&certificate_bytes)
            }
            .context("разбор CA-сертификата pfSense")?;
            builder = builder.add_root_certificate(certificate);
        }
        if skip_tls_verify {
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        let client = builder.build().context("создание HTTP-клиента pfSense")?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.to_owned(),
        })
    }

    fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}/api/v2/{}", self.base_url, path.trim_start_matches('/'));
        let response = self
            .client
            .get(url)
            .header("X-API-Key", &self.api_key)
            .send()
            .with_context(|| format!("запрос к pfSense REST API v2 ({path})"))?;
        let status = response.status();
        if !status.is_success() {
            bail!("pfSense API вернул HTTP {status}");
        }
        response
            .json::<serde_json::Value>()
            .context("разбор ответа pfSense API")
    }

    fn fetch_rule_cache(&self, rules_interface: &str) -> Result<PfsenseRuleCache> {
        let rules_interface = rules_interface.trim();
        if rules_interface.is_empty()
            || !rules_interface.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
        {
            bail!("интерфейс правил pfSense содержит недопустимые символы");
        }
        let rules = self.get_paginated_array("firewall/rules")?;
        let schedules = self.get_paginated_array("firewall/schedules")?;
        let active_schedules: std::collections::HashSet<&str> = schedules
            .iter()
            .filter(|schedule| {
                schedule.get("active").and_then(serde_json::Value::as_bool) == Some(true)
            })
            .filter_map(|schedule| schedule.get("name").and_then(serde_json::Value::as_str))
            .collect();
        let grants = rules
            .iter()
            .filter(|rule| {
                rule.get("interface")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|interfaces| {
                        interfaces
                            .iter()
                            .any(|interface| interface.as_str() == Some(rules_interface))
                    })
            })
            .filter(|rule| rule.get("disabled").and_then(serde_json::Value::as_bool) != Some(true))
            .filter(|rule| rule.get("type").and_then(serde_json::Value::as_str) == Some("pass"))
            .filter_map(|rule| {
                let schedule = rule.get("sched").and_then(serde_json::Value::as_str)?;
                if !active_schedules.contains(schedule) {
                    return None;
                }
                let description = rule
                    .get("descr")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("без описания");
                Some(PfsenseRuleGrant {
                    key: pfsense_rule_key(description),
                    description: description.to_owned(),
                    source: rule
                        .get("source")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?")
                        .to_owned(),
                    destination: rule
                        .get("destination")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("?")
                        .to_owned(),
                    schedule: schedule.to_owned(),
                })
            })
            .collect();
        Ok(PfsenseRuleCache {
            schema_version: 1,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            interface: rules_interface.to_owned(),
            rules: grants,
        })
    }

    #[allow(dead_code)]
    fn health_check(
        &self,
        rules_interface: &str,
        sql_requests: Option<&[RemoteWorkRequest]>,
    ) -> Result<String> {
        let version = self.get_json("system/restapi/version")?;
        let rules_interface = rules_interface.trim();
        if rules_interface.is_empty()
            || !rules_interface.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
        {
            bail!("интерфейс правил pfSense содержит недопустимые символы");
        }
        let rules = self.get_paginated_array("firewall/rules")?;
        let schedules = self.get_paginated_array("firewall/schedules")?;
        let version_text = version
            .pointer("/data/version")
            .or_else(|| version.pointer("/data"))
            .map(|value| value.to_string())
            .unwrap_or_else(|| "версия не указана".to_owned());
        let active_schedules: std::collections::HashSet<&str> = schedules
            .iter()
            .filter(|schedule| {
                schedule.get("active").and_then(serde_json::Value::as_bool) == Some(true)
            })
            .filter_map(|schedule| schedule.get("name").and_then(serde_json::Value::as_str))
            .collect();
        let active_rules: Vec<&serde_json::Value> = rules
            .iter()
            .filter(|rule| {
                rule.get("interface")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|interfaces| {
                        interfaces
                            .iter()
                            .any(|interface| interface.as_str() == Some(rules_interface))
                    })
            })
            .filter(|rule| rule.get("disabled").and_then(serde_json::Value::as_bool) != Some(true))
            .filter(|rule| rule.get("type").and_then(serde_json::Value::as_str) == Some("pass"))
            .filter(|rule| {
                rule.get("sched")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|schedule| active_schedules.contains(schedule))
            })
            .collect();
        let rule_lines = active_rules
            .iter()
            .map(|rule| {
                let description = rule
                    .get("descr")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("без описания");
                let source = rule
                    .get("source")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let destination = rule
                    .get("destination")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let schedule = rule
                    .get("sched")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let rule_key = pfsense_rule_key(description);
                let access = sql_requests
                    .map(|requests| {
                        let matched = requests
                            .iter()
                            .filter(|request| {
                                normalized_requester_key(&request.requester).is_some_and(|key| {
                                    rule_key == key || rule_key.starts_with(&format!("{key}_"))
                                })
                            })
                            .map(|request| request.requester.as_str())
                            .collect::<Vec<_>>();
                        if matched.is_empty() {
                            "доступ: пользователь из SQL не найден".to_owned()
                        } else {
                            format!("доступ: {}", matched.join(", "))
                        }
                    })
                    .unwrap_or_else(|| "доступ: SQL не проверен".to_owned());
                format!(
                    "{description} [{source} -> {destination}; расписание: {schedule}; {access}]"
                )
            })
            .collect::<Vec<_>>();
        Ok(format!(
            "версия API: {version_text}; активных правил firewall ({rules_interface}): {}{}",
            active_rules.len(),
            if rule_lines.is_empty() {
                String::new()
            } else {
                format!("; {}", rule_lines.join("; "))
            }
        ))
    }

    fn get_paginated_array(&self, path: &str) -> Result<Vec<serde_json::Value>> {
        // pfSense отвечает на пагинацию, но слишком маленькая страница
        // превращает чтение нескольких сотен правил в долгую серию запросов.
        const PAGE_SIZE: usize = 50;
        const MAX_PAGES: usize = 1000;
        let mut items = Vec::new();
        for page in 0..MAX_PAGES {
            let response = self.get_json(&format!(
                "{path}?limit={PAGE_SIZE}&offset={}",
                page * PAGE_SIZE
            ))?;
            let data = response
                .pointer("/data")
                .and_then(serde_json::Value::as_array)
                .with_context(|| format!("pfSense API endpoint {path} не вернул массив data"))?;
            if data.is_empty() {
                return Ok(items);
            }
            items.extend(data.iter().cloned());
        }
        bail!("pfSense API endpoint {path}: превышено ограничение страниц ({MAX_PAGES})")
    }
}

fn remote_work_request_from_row(row: tiberius::Row) -> Result<RemoteWorkRequest> {
    Ok(RemoteWorkRequest {
        request_num: get_required_str(&row, "num1")?,
        requester: get_required_str(&row, "ot_kogo")?,
        por_neisp: row.get::<i32, _>("por_neisp").unwrap_or(1),
    })
}

fn normalized_requester_key(value: &str) -> Option<String> {
    let transliterated: String = value.chars().map(transliterate_char).collect();
    let words: Vec<String> = transliterated
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let surname = words.first()?.clone();
    let initials: String = words
        .iter()
        .skip(1)
        .filter_map(|word| word.chars().next())
        .collect();
    if initials.is_empty() {
        Some(surname)
    } else {
        Some(format!("{surname}_{initials}"))
    }
}

fn transliterate_char(character: char) -> String {
    match character.to_lowercase().next().unwrap_or(character) {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "g",
        'д' => "d",
        'е' | 'ё' => "e",
        'ж' => "zh",
        'з' => "z",
        'и' => "i",
        'й' => "j",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ъ' | 'ь' => "",
        'ы' => "y",
        'э' => "e",
        'ю' => "yu",
        'я' => "ya",
        character if character.is_ascii_alphanumeric() => return character.to_string(),
        _ => " ",
    }
    .to_owned()
}

fn pfsense_rule_key(description: &str) -> String {
    description
        .split([',', ' ', ';'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
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
            "select count(*) from processed_requests where request_num = ?1 and status = 'processed'",
            params![request_num],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn record_request_processed(&self, request: &RemoteWorkRequest) -> Result<()> {
        self.conn.execute(
            "insert or replace into processed_requests (request_num, requester, rule_key, status) values (?1, ?2, null, 'processed')",
            params![request.request_num, request.requester],
        )?;
        Ok(())
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
    fn pending_numbers_are_parsed_from_poll_output() {
        let output = "OZ_RESULT fetched=3 pending=2 fingerprint=abc\nOZ_PENDING_NUMS 101, 205";
        assert_eq!(
            parse_pending_numbers(output),
            vec!["101".to_owned(), "205".to_owned()]
        );
    }

    #[test]
    fn pending_announcement_contains_request_numbers() {
        assert_eq!(
            format_pending_announcement(2, "101, 205"),
            "Необработанных заявок - 2 штук, номера: 101, 205"
        );
    }

    #[test]
    fn empty_pending_announcement_has_no_number_list() {
        assert_eq!(
            format_pending_announcement(0, "нет"),
            "Необработанных заявок нет"
        );
    }

    #[test]
    fn report_query_uses_requested_day() {
        let query = "set @d1 = '20260801';\nset @d2 = '20260825';\nselect 1;";
        let actual = query_for_report_period(query, ReportPeriod::Day, "2026-09-01").unwrap();
        assert!(actual.contains("set @d1 = '2026-09-01';"));
        assert!(actual.contains("set @d2 = '2026-09-01';"));
    }

    #[test]
    fn poll_query_uses_dynamic_lookback_window() {
        let query = "set @d1 = '20260801';\nset @d2 = '20260825';\nselect 1;";
        let actual = query_for_poll_lookback(query, 30).unwrap();
        assert!(actual.contains("set @d1 = dateadd(day, -29, cast(getdate() as date));"));
        assert!(actual.contains("set @d2 = cast(getdate() as date);"));
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
    fn quick_report_shows_processed_count_numbers_and_requesters() {
        let output = concat!(
            "OZ_REPORT period=day anchor_date=2026-09-01 total=3 processed=2 waiting=1\n",
            "OZ_REQUEST num=101 requester=Иванов status=processed\n",
            "OZ_REQUEST num=205 requester=Петров status=waiting\n",
            "OZ_REQUEST num=309 requester=Сидоров status=processed\n",
        );

        assert_eq!(
            format_quick_report(output).as_deref(),
            Some(
                "Быстрый отчет\nОбработано заявок: 2\nОбработанные заявки:\n№ 101 — Иванов\n№ 309 — Сидоров"
            )
        );
    }

    #[test]
    fn quick_report_handles_no_processed_requests() {
        let output = "OZ_REPORT period=day anchor_date=2026-09-01 total=1 processed=0 waiting=1\n";

        assert_eq!(
            format_quick_report(output).as_deref(),
            Some("Быстрый отчет\nОбработано заявок: 0\nОбработанные заявки: нет")
        );
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
    fn gui_defaults_to_auto_call_for_new_pending_requests() {
        assert!(GuiSettings::default().auto_call_on_pending);
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

    #[test]
    fn pfsense_url_must_use_http_scheme() {
        assert!(PfsenseClient::new("10.35.0.1", "test", 15, "", false).is_err());
        assert!(PfsenseClient::new("https://10.35.0.1", "test", 15, "", false).is_ok());
        assert!(PfsenseClient::new("https://10.35.0.1", "test", 15, "", true).is_ok());
    }

    #[test]
    fn requester_names_match_pfsense_login_prefixes() {
        let requester = normalized_requester_key("Рачков Илья Игоревич").unwrap();
        let rule_key = pfsense_rule_key("rachkov_ii_syk83, Приказ №25-132");
        assert_eq!(requester, "rachkov_ii");
        assert!(rule_key == requester || rule_key.starts_with(&format!("{requester}_")));
    }
}
