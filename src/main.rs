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
    query: Option<String>,
    query_file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PfsenseConfig {
    base_url: String,
    token_env: String,
    insecure_tls: bool,
    timeout_seconds: u64,
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
    let pfsense = PfsenseClient::new(&config.pfsense)?;

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

        pfsense.apply(&op).await?;
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
    let connection_string = std::env::var(&config.connection_string_env)
        .with_context(|| format!("{} is required", config.connection_string_env))?;
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

impl SqlConfig {
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
}
