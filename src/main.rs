use chrono::Local;
use clap::{Parser, Subcommand};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};
use togra::audit::AuditLog;
use togra::harness::EchoHarness;
use togra::manifest::{OutputSchema, SandboxProfile, TaskManifest, TrustedProjects};
use togra::policy::Policy;
use togra::queue::InMemoryQueue;
use togra::runner::{Runner, Tick};
use togra::sandbox::DirSandbox;

#[derive(Parser)]
#[command(version, about = "Local runner for Tokens of Gratitude")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a runner keypair (hex seed, mode 0600) and print the runner id.
    Keygen { out: PathBuf },
    /// Show the audit log.
    Audit { log: PathBuf },
    /// Create a config directory with a runner key and a strict starter config.
    Init {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Run the daemon in the foreground (what the service unit invokes).
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Sign in the daemon's Claude subscription: runs `claude setup-token`, then stores the token.
    Login {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show daemon status from the state directory.
    Status {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Write a systemd (Linux) or launchd (macOS) user unit for the daemon.
    InstallService {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Run one signed task end to end against an in-memory queue and an echo harness.
    Demo,
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME is not set"))
}

fn default_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| home().join(".config"), PathBuf::from).join("togra")
}

fn config_path(c: Option<PathBuf>) -> PathBuf {
    c.unwrap_or_else(|| default_dir().join("config.json"))
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Init { dir } => {
            let dir = dir.unwrap_or_else(default_dir);
            fs::create_dir_all(&dir)?;
            let path = dir.join("config.json");
            if path.exists() {
                return Err(format!("{} already exists", path.display()).into());
            }
            let cfg = togra::config::Config::starter(&dir);
            let id = hex::encode(cfg.load_or_create_key()?.verifying_key().to_bytes());
            fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
            println!("wrote {}\nrunner id: {id}\nNothing will run until you add a trusted project, allowed kinds and a share to the config.", path.display());
        }
        Cmd::Run { config } => {
            let cfg = togra::config::Config::load(&config_path(config))?;
            togra::daemon::run(cfg, shutdown_signal()).await?;
        }
        Cmd::Login { config } => {
            let cfg = togra::config::Config::load(&config_path(config))?;
            let token_file = match &cfg.harness {
                togra::config::HarnessConfig::Claude { token_file, .. } => token_file.clone().unwrap_or_else(|| cfg.token_path()),
                _ => return Err("config.harness.kind is not `claude`".into()),
            };
            fs::create_dir_all(&cfg.state_dir)?;
            println!("Running `claude setup-token`. Complete the browser sign-in, then paste the token it prints.");
            std::process::Command::new("claude").arg("setup-token").status()?;
            let token = rpassword::prompt_password("Paste token (input hidden): ")?;
            if token.trim().is_empty() {
                return Err("no token entered".into());
            }
            togra::claude_cli::save_token(&token_file, &token)?;
            println!("saved to {} (mode 600). It never leaves this machine.", token_file.display());
        }
        Cmd::Status { config } => {
            let cfg = togra::config::Config::load(&config_path(config))?;
            match togra::daemon::Status::read(&cfg.state_dir) {
                Some(s) => println!("{}", serde_json::to_string_pretty(&s)?),
                None => println!("no status yet (daemon has not run)"),
            }
        }
        Cmd::InstallService { config } => {
            let cfg = config_path(config);
            let cfg = fs::canonicalize(&cfg).map_err(|e| format!("{}: {e}", cfg.display()))?;
            let (path, enable) = togra::service::install(&home(), &std::env::current_exe()?, &cfg)?;
            println!("wrote {}\nenable it with: {enable}", path.display());
        }
        Cmd::Keygen { out } => {
            let key = togra::manifest::generate_key();
            fs::write(&out, hex::encode(key.to_bytes()))?;
            fs::set_permissions(&out, fs::Permissions::from_mode(0o600))?;
            println!("runner id: {}", hex::encode(key.verifying_key().to_bytes()));
        }
        Cmd::Audit { log } => {
            for e in AuditLog::new(log).entries()? {
                println!("{} {:<9} {} {} tokens={} {}", e.ts.format("%F %T"), e.outcome, e.project_id, e.task_id, e.tokens, e.detail);
            }
        }
        Cmd::Demo => demo()?,
    }
    Ok(())
}

fn demo() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join("togra-demo");
    fs::create_dir_all(&dir)?;
    let project_key = togra::manifest::generate_key();
    let mut trusted = TrustedProjects::default();
    trusted.insert("demo-project", project_key.verifying_key());

    let policy = Policy {
        daily_token_cap: 10_000,
        project_shares: BTreeMap::from([("demo-project".into(), 1)]),
        allowed_kinds: vec!["summarise".into()],
        quiet_hours: None,
        review_before_submit: false,
        max_profile: SandboxProfile::default(),
        abort_margin_pct: 25,
        available_tools: vec!["echo".into()],
        allow_skills: false,
        allowed_mcp_hosts: vec![],
        max_context_bytes: 64 * 1024,
    };
    let queue = InMemoryQueue::default();
    queue.post(
        TaskManifest {
            id: "t1".into(),
            project_id: "demo-project".into(),
            kind: "summarise".into(),
            inputs: "0".repeat(64),
            prompt: "Summarise the README".into(),
            tool_requirements: vec!["echo".into()],
            sandbox_profile: SandboxProfile::default(),
            cost_estimate: 500,
            output_schema: OutputSchema { format: "text".into(), max_bytes: 4096 },
            redundancy: 1,
            context: Default::default(),
            signature: None,
        }
        .sign(&project_key)?,
    );

    let audit_path = dir.join("audit.jsonl");
    let mut runner = Runner::new(
        policy, trusted, togra::manifest::generate_key(), queue,
        EchoHarness { tokens_per_run: 400 }, DirSandbox { root: dir.join("work") },
        |_: &TaskManifest, _: &togra::result::TaskResult| true, AuditLog::new(&audit_path),
    );
    let outcome: Tick = runner.tick(Local::now())?;
    println!("{outcome:?}; audit log at {}", audit_path.display());
    Ok(())
}
