use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use reqwest::{Client as HttpClient, Method};
use rusqlite::{Connection, params};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tiberius::{Client as MssqlClient, Config as MssqlConfig};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::{info, warn};
use url::Url;

#[derive(Parser)]
#[command(version, about = "Apply pfSense REST API desired state from MSSQL")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Plan(CommonArgs),
    Run(RunArgs),
    ProcessRequests(RunArgs),
}

#[derive(Args, Clone)]
struct CommonArgs {
    #[arg(long, env = "ORCH_CONFIG", default_value = "config.toml")]
    config: String,
}

#[derive(Args, Clone)]
struct RunArgs {
    #[command(flatten)]
    common: CommonArgs,

    #[arg(long)]
    once: bool,

    #[arg(long, conflicts_with = "apply")]
    dry_run: bool,

    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Deserialize)]
struct AppConfig {
    runtime: RuntimeConfig,
    mssql: SqlConfig,
    requests: Option<RequestsConfig>,
    pfsense: PfsenseConfig,
}

#[derive(Debug, Deserialize)]
struct RuntimeConfig {
    interval_seconds: u64,
    audit_db_path: String,
}

#[derive(Debug, Deserialize)]
struct SqlConfig {
    connection_string_env: String,
    default_connection_string: Option<String>,
    query: Option<String>,
    query_file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RequestsConfig {
    query_file: String,
    mapping_file: String,
    rdp_port: u16,
    mark_unapproved_as_seen: bool,
}

#[derive(Debug, Deserialize)]
struct PfsenseConfig {
    base_url: String,
    token_env: String,
    insecure_tls: bool,
    timeout_seconds: u64,
    remote_work_access: Option<PfsenseOperationTemplate>,
}

#[derive(Debug, Deserialize)]
struct PfsenseOperationTemplate {
    method: String,
    path: String,
    body_template: String,
}

#[derive(Debug, Clone)]
struct DesiredOperation {
    rule_key: String,
    action: String,
    method: String,
    path: String,
    body_json: Option<String>,
    desired_hash: String,
}

#[derive(Debug, Deserialize)]
struct WorkstationMappings {
    employee: Vec<EmployeeAccess>,
}

#[derive(Debug, Deserialize)]
struct EmployeeAccess {
    requester: String,
    vpn_user: String,
    workstation_host: String,
    enabled: bool,
}

#[derive(Debug, Clone)]
struct RemoteWorkRequest {
    request_num: String,
    requester: String,
    date_z: String,
    date_n: String,
    time_n: String,
    date_k: String,
    time_k: String,
    reason: String,
    por_neisp: i32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Plan(args) => {
            let config = load_config(&args.config)?;
            print_plan(&config)
        }
        Command::Run(args) => {
            let config = load_config(&args.common.config)?;
            let apply = args.apply;

            if !args.once {
                run_loop(&config, apply).await
            } else {
                run_once(&config, apply).await
            }
        }
        Command::ProcessRequests(args) => {
            let config = load_config(&args.common.config)?;
            process_requests(&config, args.apply).await
        }
    }
}

fn load_config(path: &str) -> Result<AppConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
    toml::from_str(&raw).with_context(|| format!("parse config {path}"))
}

fn print_plan(config: &AppConfig) -> Result<()> {
    let base = Url::parse(&config.pfsense.base_url).context("parse pfsense.base_url")?;

    println!(
        "MSSQL connection env: {}",
        config.mssql.connection_string_env
    );
    println!("pfSense API: {}", base);
    println!("Audit DB: {}", config.runtime.audit_db_path);
    println!("Interval: {}s", config.runtime.interval_seconds);
    println!("pfSense token env: {}", config.pfsense.token_env);
    println!("SQL query source: {}", config.mssql.query_source());
    if let Some(requests) = &config.requests {
        println!("Requests query file: {}", requests.query_file);
        println!("Workstation mapping file: {}", requests.mapping_file);
        println!("RDP port: {}", requests.rdp_port);
    }

    Ok(())
}

async fn process_requests(config: &AppConfig, apply: bool) -> Result<()> {
    let requests_config = config
        .requests
        .as_ref()
        .context("requests section is required for process-requests")?;
    let mappings = load_workstation_mappings(&requests_config.mapping_file)?;
    let audit = Audit::open(&config.runtime.audit_db_path)?;
    let pfsense = if apply {
        Some(PfsenseClient::new(&config.pfsense)?)
    } else {
        None
    };
    let query = fs::read_to_string(&requests_config.query_file)
        .with_context(|| format!("read request query file {}", requests_config.query_file))?;
    let requests = fetch_remote_work_requests(&config.mssql, &query).await?;

    info!(count = requests.len(), "fetched remote work requests");

    for request in requests {
        if audit.is_request_processed(&request.request_num)? {
            info!(
                request_num = request.request_num,
                "request already processed"
            );
            continue;
        }

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

        let Some(employee) = mappings.employee.iter().find(|item| {
            item.enabled
                && item
                    .requester
                    .eq_ignore_ascii_case(request.requester.trim())
        }) else {
            warn!(
                request_num = request.request_num,
                requester = request.requester,
                "no enabled workstation mapping for requester"
            );
            continue;
        };

        let op = remote_work_operation(config, requests_config, &request, employee)?;

        if audit.is_applied(&op.rule_key, &op.desired_hash)? {
            audit.record_request_processed(&request, &op, "already_applied")?;
            continue;
        }

        if !apply {
            warn!(
                request_num = request.request_num,
                requester = request.requester,
                vpn_user = employee.vpn_user,
                workstation_host = employee.workstation_host,
                "dry run: would grant OpenVPN RDP access"
            );
            continue;
        }

        pfsense
            .as_ref()
            .context("pfSense client is required when --apply is used")?
            .apply(&op)
            .await?;
        audit.record_applied(&op)?;
        audit.record_request_processed(&request, &op, "applied")?;
        info!(
            request_num = request.request_num,
            requester = request.requester,
            vpn_user = employee.vpn_user,
            workstation_host = employee.workstation_host,
            "remote access granted"
        );
    }

    Ok(())
}

async fn run_loop(config: &AppConfig, apply: bool) -> Result<()> {
    loop {
        run_once(config, apply).await?;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.runtime.interval_seconds)) => {}
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                return Ok(());
            }
        }
    }
}

async fn run_once(config: &AppConfig, apply: bool) -> Result<()> {
    let audit = Audit::open(&config.runtime.audit_db_path)?;
    let operations = fetch_desired_operations(&config.mssql).await?;
    let pfsense = if apply {
        Some(PfsenseClient::new(&config.pfsense)?)
    } else {
        None
    };

    for op in operations {
        if audit.is_applied(&op.rule_key, &op.desired_hash)? {
            info!(
                rule_key = op.rule_key,
                action = op.action,
                "operation already applied"
            );
            continue;
        }

        if !apply {
            warn!(
                rule_key = op.rule_key,
                action = op.action,
                method = op.method,
                path = op.path,
                desired_hash = op.desired_hash,
                "dry run: would apply operation"
            );
            continue;
        }

        pfsense
            .as_ref()
            .context("pfSense client is required when --apply is used")?
            .apply(&op)
            .await?;
        audit.record_applied(&op)?;
        info!(
            rule_key = op.rule_key,
            action = op.action,
            "operation applied"
        );
    }

    Ok(())
}

async fn fetch_desired_operations(config: &SqlConfig) -> Result<Vec<DesiredOperation>> {
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
        .simple_query(config.load_query()?.as_str())
        .await
        .context("execute MSSQL desired-state query")?
        .into_results()
        .await
        .context("read MSSQL rows")?;

    let mut operations = Vec::new();
    for result_set in rows {
        for row in result_set {
            operations.push(operation_from_row(row)?);
        }
    }

    Ok(operations)
}

async fn fetch_remote_work_requests(
    config: &SqlConfig,
    query: &str,
) -> Result<Vec<RemoteWorkRequest>> {
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
    fn connection_string(&self) -> Result<String> {
        match std::env::var(&self.connection_string_env) {
            Ok(value) => Ok(value),
            Err(_) => self
                .default_connection_string
                .clone()
                .with_context(|| format!("{} is required", self.connection_string_env)),
        }
    }

    fn query_source(&self) -> &str {
        if self.query_file.is_some() {
            "query_file"
        } else {
            "query"
        }
    }

    fn load_query(&self) -> Result<String> {
        match (&self.query, &self.query_file) {
            (Some(_), Some(_)) => bail!("mssql.query and mssql.query_file are mutually exclusive"),
            (Some(query), None) => Ok(query.clone()),
            (None, Some(path)) => {
                fs::read_to_string(path).with_context(|| format!("read SQL query file {path}"))
            }
            (None, None) => bail!("one of mssql.query or mssql.query_file is required"),
        }
    }
}

fn load_workstation_mappings(path: &str) -> Result<WorkstationMappings> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("read workstation mapping {path}"))?;
    toml::from_str(&raw).with_context(|| format!("parse workstation mapping {path}"))
}

fn remote_work_request_from_row(row: tiberius::Row) -> Result<RemoteWorkRequest> {
    Ok(RemoteWorkRequest {
        request_num: get_required_str(&row, "num1")?,
        requester: get_required_str(&row, "ot_kogo")?,
        date_z: get_optional_str(&row, "date_z").unwrap_or_default(),
        date_n: get_optional_str(&row, "date_n").unwrap_or_default(),
        time_n: get_optional_str(&row, "time_n").unwrap_or_default(),
        date_k: get_optional_str(&row, "date_k").unwrap_or_default(),
        time_k: get_optional_str(&row, "time_k").unwrap_or_default(),
        reason: get_optional_str(&row, "prich").unwrap_or_default(),
        por_neisp: row.get::<i32, _>("por_neisp").unwrap_or(1),
    })
}

fn remote_work_operation(
    config: &AppConfig,
    requests_config: &RequestsConfig,
    request: &RemoteWorkRequest,
    employee: &EmployeeAccess,
) -> Result<DesiredOperation> {
    let template = config
        .pfsense
        .remote_work_access
        .as_ref()
        .context("pfsense.remote_work_access section is required")?;
    let body_json = render_remote_work_template(
        &template.body_template,
        request,
        employee,
        requests_config.rdp_port,
    );
    let rule_key = format!("remote-work:{}:{}", request.request_num, employee.vpn_user);
    let action = "grant_openvpn_rdp".to_owned();
    let method = template.method.to_uppercase();
    let path = template.path.clone();
    let desired_hash = hash_operation(&method, &path, Some(&body_json));

    Ok(DesiredOperation {
        rule_key,
        action,
        method,
        path,
        body_json: Some(body_json),
        desired_hash,
    })
}

fn render_remote_work_template(
    template: &str,
    request: &RemoteWorkRequest,
    employee: &EmployeeAccess,
    rdp_port: u16,
) -> String {
    let mut rendered = template.to_owned();
    let replacements = [
        ("request_num", request.request_num.as_str()),
        ("requester", request.requester.as_str()),
        ("vpn_user", employee.vpn_user.as_str()),
        ("workstation_host", employee.workstation_host.as_str()),
        ("date_z", request.date_z.as_str()),
        ("date_n", request.date_n.as_str()),
        ("time_n", request.time_n.as_str()),
        ("date_k", request.date_k.as_str()),
        ("time_k", request.time_k.as_str()),
        ("reason", request.reason.as_str()),
    ];

    for (key, value) in replacements {
        rendered = rendered.replace(&format!("{{{{{key}}}}}"), &json_escape(value));
    }
    rendered.replace("{{rdp_port}}", &rdp_port.to_string())
}

fn json_escape(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"\"".to_owned())
        .trim_matches('"')
        .to_owned()
}

fn operation_from_row(row: tiberius::Row) -> Result<DesiredOperation> {
    let rule_key = get_required_str(&row, "rule_key")?;
    let action = get_required_str(&row, "action")?;
    let method = get_required_str(&row, "method")?.to_uppercase();
    let path = get_required_str(&row, "path")?;
    let body_json = get_optional_str(&row, "body_json");
    let desired_hash = get_optional_str(&row, "desired_hash")
        .unwrap_or_else(|| hash_operation(&method, &path, body_json.as_deref()));

    if !path.starts_with('/') {
        bail!("path for {rule_key} must start with /");
    }

    Ok(DesiredOperation {
        rule_key,
        action,
        method,
        path,
        body_json,
        desired_hash,
    })
}

fn get_required_str(row: &tiberius::Row, name: &str) -> Result<String> {
    get_optional_str(row, name)
        .with_context(|| format!("required MSSQL column {name} is null or missing"))
}

fn get_optional_str(row: &tiberius::Row, name: &str) -> Option<String> {
    row.get::<&str, _>(name).map(str::to_owned)
}

fn hash_operation(method: &str, path: &str, body_json: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\n");
    hasher.update(path.as_bytes());
    hasher.update(b"\n");
    hasher.update(body_json.unwrap_or("").as_bytes());
    format!("{:x}", hasher.finalize())
}

struct PfsenseClient {
    http: HttpClient,
    base_url: Url,
    token: String,
}

impl PfsenseClient {
    fn new(config: &PfsenseConfig) -> Result<Self> {
        let token = std::env::var(&config.token_env)
            .with_context(|| format!("{} is required", config.token_env))?;

        let http = HttpClient::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .danger_accept_invalid_certs(config.insecure_tls)
            .build()
            .context("build HTTP client")?;

        Ok(Self {
            http,
            base_url: parse_base_url(&config.base_url)?,
            token,
        })
    }

    async fn apply(&self, op: &DesiredOperation) -> Result<()> {
        let method = Method::from_bytes(op.method.as_bytes())
            .with_context(|| format!("invalid HTTP method {}", op.method))?;
        let url = self
            .base_url
            .join(op.path.trim_start_matches('/'))
            .with_context(|| format!("join pfSense path {}", op.path))?;

        let mut request = self.http.request(method, url).bearer_auth(&self.token);

        if let Some(body) = &op.body_json {
            let value: serde_json::Value = serde_json::from_str(body)
                .with_context(|| format!("body_json is invalid for {}", op.rule_key))?;
            request = request.json(&value);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("send pfSense request for {}", op.rule_key))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!(
                "pfSense request failed for {}: {} {}",
                op.rule_key,
                status,
                body
            );
        }

        Ok(())
    }
}

fn parse_base_url(raw: &str) -> Result<Url> {
    let normalized = if raw.ends_with('/') {
        raw.to_owned()
    } else {
        format!("{raw}/")
    };
    Url::parse(&normalized).context("parse pfsense.base_url")
}

struct Audit {
    conn: Connection,
}

impl Audit {
    fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open audit DB {path}"))?;
        conn.execute_batch(
            "create table if not exists applied_operations (
                rule_key text not null,
                desired_hash text not null,
                action text not null,
                applied_at text not null default current_timestamp,
                primary key (rule_key, desired_hash)
            );
            create table if not exists processed_requests (
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

    fn is_applied(&self, rule_key: &str, desired_hash: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "select count(*) from applied_operations where rule_key = ?1 and desired_hash = ?2",
            params![rule_key, desired_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn record_applied(&self, op: &DesiredOperation) -> Result<()> {
        self.conn.execute(
            "insert or ignore into applied_operations (rule_key, desired_hash, action) values (?1, ?2, ?3)",
            params![op.rule_key, op.desired_hash, op.action],
        )?;
        Ok(())
    }

    fn is_request_processed(&self, request_num: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "select count(*) from processed_requests where request_num = ?1",
            params![request_num],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn record_request_processed(
        &self,
        request: &RemoteWorkRequest,
        op: &DesiredOperation,
        status: &str,
    ) -> Result<()> {
        self.conn.execute(
            "insert or replace into processed_requests (request_num, requester, rule_key, status) values (?1, ?2, ?3, ?4)",
            params![request.request_num, request.requester, op.rule_key, status],
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
    fn pfsense_base_url_preserves_api_prefix() {
        let base = parse_base_url("https://pfsense.example.local/api/v2").unwrap();
        let url = base.join("firewall/rule").unwrap();

        assert_eq!(
            url.as_str(),
            "https://pfsense.example.local/api/v2/firewall/rule"
        );
    }

    #[test]
    fn operation_hash_is_stable() {
        let left = hash_operation("POST", "/firewall/rule", Some("{\"a\":1}"));
        let right = hash_operation("POST", "/firewall/rule", Some("{\"a\":1}"));

        assert_eq!(left, right);
    }

    #[test]
    fn remote_work_template_renders_request_context() {
        let request = RemoteWorkRequest {
            request_num: "42".to_owned(),
            requester: "Ivanov".to_owned(),
            date_z: "2026-08-27".to_owned(),
            date_n: "2026-08-28".to_owned(),
            time_n: "09:00-18:00".to_owned(),
            date_k: String::new(),
            time_k: String::new(),
            reason: "test".to_owned(),
            por_neisp: 0,
        };
        let employee = EmployeeAccess {
            requester: "Ivanov".to_owned(),
            vpn_user: "ivanov_i".to_owned(),
            workstation_host: "10.32.5.121".to_owned(),
            enabled: true,
        };

        let rendered = render_remote_work_template(
            r#"{"source":"{{vpn_user}}","destination":"{{workstation_host}}","port":{{rdp_port}},"descr":"{{request_num}} {{date_n}}"}"#,
            &request,
            &employee,
            3389,
        );

        assert_eq!(
            rendered,
            r#"{"source":"ivanov_i","destination":"10.32.5.121","port":3389,"descr":"42 2026-08-28"}"#
        );
    }
}
