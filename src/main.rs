use chrono::Local;
use clap::{Parser, Subcommand};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};
use toto::audit::AuditLog;
use toto::harness::EchoHarness;
use toto::manifest::{OutputSchema, SandboxProfile, TaskManifest, TrustedProjects};
use toto::policy::Policy;
use toto::queue::InMemoryQueue;
use toto::runner::{Runner, Tick};
use toto::sandbox::DirSandbox;

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
    /// Run the daemon in the foreground (what the service unit invokes). With --once, process
    /// available tasks until none are left, print each outcome and exit (for testing).
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        once: bool,
    },
    /// Generate a project signing key (hex seed, mode 0600) and print its public key.
    ProjectKey { out: PathBuf },
    /// Sign a task manifest (JSON, no signature) with a project key and put it in the queue dir.
    PostTask {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Directory to pack as the task's input bundle (sets `inputs` to its hash).
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Directory laid out like a project root with `.mcp.json`, `.claude/skills/` and/or
        /// `AGENTS.md`; packed as the task's context (anything else in it is rejected).
        #[arg(long)]
        context: Option<PathBuf>,
        task: PathBuf,
    },
    /// Write a result's artifacts (changed files) into a new directory and list deletions.
    ExtractResult {
        /// A result file from `<queue_dir>/results/`.
        result: PathBuf,
        /// Directory to create.
        out: PathBuf,
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
    /// Check the whole setup (sandbox, network fence, nested sandbox, credentials, harness) and
    /// report what works, what is risky and what is missing. Exits 1 if anything failed.
    Doctor {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Create (and with --apply, install) the firewalled docker network that tasks with egress
    /// rules run on: no route to private ranges, other containers or this host. Needs root.
    NetSetup {
        #[arg(long, default_value = toto::netfence::DEFAULT_NETWORK)]
        name: String,
        #[arg(long, default_value = toto::netfence::DEFAULT_SUBNET)]
        subnet: String,
        #[arg(long, default_value = "docker")]
        bin: String,
        /// Run the script instead of printing it.
        #[arg(long)]
        apply: bool,
        /// Remove the rules and the network.
        #[arg(long)]
        remove: bool,
    },
    /// Serve a spool directory over the queue protocol (reference coordinator for pilots).
    ServeQueue {
        /// Spool directory (the same layout `post-task` writes to).
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: String,
        /// File holding the bearer token clients must send. Without it the server is open.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Run one signed task end to end against an in-memory queue and an echo harness.
    Demo,
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME is not set"))
}

fn default_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| home().join(".config"), PathBuf::from).join("toto")
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
            let cfg = toto::config::Config::starter(&dir);
            let id = hex::encode(cfg.load_or_create_key()?.verifying_key().to_bytes());
            fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
            println!("wrote {}\nrunner id: {id}\nNothing will run until you add a trusted project, allowed kinds and a share to the config.", path.display());
        }
        Cmd::Run { config, once: false } => {
            let cfg = toto::config::Config::load(&config_path(config))?;
            toto::daemon::run(cfg, shutdown_signal()).await?;
        }
        Cmd::Run { config, once: true } => {
            let cfg = toto::config::Config::load(&config_path(config))?;
            let mut runner = cfg.build()?;
            runner.sandbox.probe()?;
            runner.harness.probe()?;
            println!("sandbox and harness probes passed");
            loop {
                match runner.tick(Local::now())? {
                    Tick::Idle => break,
                    other => println!("{other:?}"),
                }
            }
            println!("queue empty; audit log: {}", cfg.state_dir.join("audit.jsonl").display());
        }
        Cmd::Doctor { config } => {
            let cfg = toto::config::Config::load(&config_path(config))?;
            let checks = toto::doctor::run_all(&cfg);
            for c in &checks {
                println!("{c}");
            }
            if !toto::doctor::passed(&checks) {
                std::process::exit(1);
            }
        }
        Cmd::NetSetup { name, subnet, bin, apply, remove } => {
            let dns = toto::netfence::resolvers(&fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
            let script = if remove { toto::netfence::teardown_script(&bin, &name, &subnet, &dns) } else { toto::netfence::script(&bin, &name, &subnet, &dns) };
            if !apply {
                println!("# run as root (or re-run with --apply):\n{script}# then set \"network\": \"{name}\" in the docker sandbox config");
            } else if !std::process::Command::new("sh").args(["-c", &script]).status()?.success() {
                return Err("the script failed (are you root, and is iptables available?)".into());
            } else if remove {
                println!("removed the fence rules and network `{name}`");
            } else {
                println!("done; set \"network\": \"{name}\" in the docker sandbox config, then run `toto doctor`");
            }
        }
        Cmd::ServeQueue { dir, addr, token_file } => {
            let token = token_file.as_deref().map(toto::claude_cli::read_secret).transpose()?;
            if token.is_none() && !addr.starts_with("127.") {
                eprintln!("warning: serving without a token on {addr}; anyone who can reach it can claim tasks and read bundles");
            }
            let server = toto::http_queue::serve(std::sync::Arc::new(toto::queue::DirQueue::new(dir)?), &addr, token)?;
            println!("serving the queue protocol on http://{}", server.addr);
            shutdown_signal().await;
            server.stop();
        }
        Cmd::ProjectKey { out } => {
            let key = toto::manifest::generate_key();
            fs::write(&out, hex::encode(key.to_bytes()))?;
            fs::set_permissions(&out, fs::Permissions::from_mode(0o600))?;
            println!("public key: {}", hex::encode(key.verifying_key().to_bytes()));
        }
        Cmd::ExtractResult { result, out } => {
            let r: toto::result::SignedResult = serde_json::from_slice(&fs::read(&result)?)?;
            let body = r.open()?; // verifies the runner's signature, output hash and artifacts hash
            println!("result for {} by runner {}…: {} tokens", body.task_id, &body.runner_id[..12], body.tokens_used);
            let records = r.artifact_records(1 << 30)?;
            if records.is_empty() {
                println!("no artifacts in this result (signature ok)");
            }
            toto::archive::unpack_to(&out, &records)?;
            for rec in &records {
                match rec {
                    toto::archive::Record::File { path, data, .. } => println!("file    {path} ({} bytes)", data.len()),
                    toto::archive::Record::Deleted { path } => println!("deleted {path}"),
                }
            }
        }
        Cmd::PostTask { key, config, bundle, context, task } => {
            let cfg = toto::config::Config::load(&config_path(config))?;
            let seed: [u8; 32] = hex::decode(fs::read_to_string(&key)?.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("project key must be a 32-byte hex seed")?;
            let mut manifest: TaskManifest = serde_json::from_slice(&fs::read(&task)?)?;
            let queue = toto::queue::DirQueue::new(&cfg.queue_dir)?;
            if let Some(dir) = bundle {
                let records = toto::archive::pack_dir(&dir, toto::archive::Limits::new(cfg.policy.max_input_bytes))?;
                manifest.inputs = queue.post_bundle(&toto::archive::to_bytes(&records)?)?;
                println!("bundled {} files from {} as {}", records.len(), dir.display(), manifest.inputs);
            }
            if let Some(dir) = context {
                let limits = toto::archive::Limits::new(cfg.policy.max_context_bytes.max(1 << 20));
                let bytes = toto::archive::to_bytes(&toto::archive::pack_dir(&dir, limits)?)?;
                let ctx = toto::context::ProjectContext::parse(&bytes, limits)?; // same checks the runner applies
                manifest.context = Some(queue.post_bundle(&bytes)?);
                println!("context from {}: {}", dir.display(), ctx.summary());
            }
            let signed = manifest.sign(&ed25519_dalek::SigningKey::from_bytes(&seed))?;
            queue.post(&signed)?;
            println!("posted {} to {}", manifest.id, cfg.queue_dir.display());
        }
        Cmd::Login { config } => {
            let cfg = toto::config::Config::load(&config_path(config))?;
            let token_file = match &cfg.harness {
                toto::config::HarnessConfig::Claude { token_file, .. } => token_file.clone().unwrap_or_else(|| cfg.token_path()),
                _ => return Err("config.harness.kind is not `claude`".into()),
            };
            fs::create_dir_all(&cfg.state_dir)?;
            println!("Running `claude setup-token`. Complete the browser sign-in, then paste the token it prints.");
            std::process::Command::new("claude").arg("setup-token").status()?;
            let token = rpassword::prompt_password("Paste token (input hidden): ")?;
            if token.trim().is_empty() {
                return Err("no token entered".into());
            }
            toto::claude_cli::save_token(&token_file, &token)?;
            println!("saved to {} (mode 600). It never leaves this machine.", token_file.display());
        }
        Cmd::Status { config } => {
            let cfg = toto::config::Config::load(&config_path(config))?;
            match toto::daemon::Status::read(&cfg.state_dir) {
                Some(s) => println!("{}", serde_json::to_string_pretty(&s)?),
                None => println!("no status yet (daemon has not run)"),
            }
        }
        Cmd::InstallService { config } => {
            let cfg = config_path(config);
            let cfg = fs::canonicalize(&cfg).map_err(|e| format!("{}: {e}", cfg.display()))?;
            let (path, enable) = toto::service::install(&home(), &std::env::current_exe()?, &cfg)?;
            println!("wrote {}\nenable it with: {enable}", path.display());
        }
        Cmd::Keygen { out } => {
            let key = toto::manifest::generate_key();
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
    let dir = std::env::temp_dir().join("toto-demo");
    fs::create_dir_all(&dir)?;
    let project_key = toto::manifest::generate_key();
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
        allow_context: false,
                allow_stdio_mcp: false,
        allowed_mcp_hosts: vec![],
        max_context_bytes: 64 * 1024,
                max_input_bytes: 64 * 1024 * 1024,
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
            output_schema: OutputSchema { format: "text".into(), max_bytes: 4096, max_artifact_bytes: 0 },
            redundancy: 1,
            context: Default::default(),
        }
        .sign(&project_key)?,
    );

    let audit_path = dir.join("audit.jsonl");
    let mut runner = Runner::new(
        policy, trusted, toto::manifest::generate_key(), queue,
        EchoHarness { tokens_per_run: 400 }, DirSandbox { root: dir.join("work") },
        |_: &TaskManifest, _: &toto::result::SignedResult| true, AuditLog::new(&audit_path),
    );
    let outcome: Tick = runner.tick(Local::now())?;
    println!("{outcome:?}; audit log at {}", audit_path.display());
    Ok(())
}
