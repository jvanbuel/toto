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
    /// Run one signed task end to end against an in-memory queue and an echo harness.
    Demo,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
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
