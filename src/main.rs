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
#[command(version, about = "toto: donate unused AI capacity to projects you choose")]
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
    /// Choose which projects your runner supports: add, inspect, update, list or remove.
    Projects {
        #[command(subcommand)]
        cmd: ProjectsCmd,
        #[arg(long, global = true)]
        config: Option<PathBuf>,
    },
    /// The signed project directory: list it, or (maintainers) add, remove and sign entries.
    Directory {
        #[command(subcommand)]
        cmd: DirectoryCmd,
    },
    /// Check the whole setup (sandbox, network fence, approved environments, credentials, harness)
    /// and report what works, what is risky and what is missing. Exits 1 if anything failed.
    Doctor {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Create (and with --apply, install) the firewalled docker network that agents needing a
    /// network run on: no route to private ranges, other containers or this host. Needs root.
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
    /// Project side: generate a project signing key (hex seed, mode 0600) and print its public key.
    ProjectKey { out: PathBuf },
    /// Project side: sign a task manifest (JSON, no signature) with a project key and post it.
    PostTask {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Directory to pack as the task's input bundle (sets `inputs` to its hash).
        #[arg(long)]
        bundle: Option<PathBuf>,
        task: PathBuf,
        /// Post to GitHub issues in this repository (`owner/name`) instead of the spool directory.
        /// The token needs to create issues and labels, and to upload release assets for bundles.
        #[arg(long)]
        github: Option<String>,
        #[arg(long, requires = "github")]
        github_token_file: Option<PathBuf>,
        #[arg(long, default_value = toto::github_queue::DEFAULT_API)]
        github_api: String,
    },
    /// Project side: open a pull request for every finished task's result (run it on a schedule,
    /// e.g. from a GitHub Action in the project repository; see docs/github-queue.md).
    ResultsToPr {
        /// `owner/name`
        repo: String,
        /// Checkout of the project repository with push access to `origin`.
        #[arg(long, default_value = ".")]
        repo_dir: PathBuf,
        #[arg(long, default_value = "main")]
        base: String,
        /// A project allowed to post tasks, as `id=<hex public key>` (repeatable). Only tasks it
        /// signed are acted on.
        #[arg(long = "project", required = true)]
        projects: Vec<String>,
        /// Token file; default: the GITHUB_TOKEN environment variable.
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long, default_value = toto::github_queue::DEFAULT_API)]
        api: String,
        /// Stop opening PRs while this many toto PRs are open.
        #[arg(long, default_value_t = 10)]
        max_open: usize,
        /// Extra path (prefix if it ends in `/`) a result may not touch; repeatable. `.github/`,
        /// `.gitlab-ci.yml`, `.git/` and a few more are always protected.
        #[arg(long = "protect")]
        protect: Vec<String>,
    },
    /// Project side: download the verified results found on a GitHub queue's issues, one file per
    /// result, ready for `extract-result`.
    GithubResults {
        /// `owner/name`
        repo: String,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long, default_value = toto::github_queue::DEFAULT_API)]
        api: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write a result's artifacts (changed files) into a new directory and list deletions.
    ExtractResult {
        /// A result file.
        result: PathBuf,
        /// Directory to create.
        out: PathBuf,
    },
    /// Run one signed task end to end against an in-memory queue and an echo harness.
    Demo,
}

#[derive(Subcommand)]
enum DirectoryCmd {
    /// Show the projects in the signed directory your config points at.
    List {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Maintainers: read a project's own files from GitHub into the unsigned directory file.
    Add {
        /// `owner/name`
        repo: String,
        /// The unsigned directory file to edit (created if missing).
        #[arg(long, default_value = "projects.unsigned.json")]
        file: PathBuf,
        #[arg(long, default_value = toto::github_queue::DEFAULT_API)]
        api: String,
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Maintainers: drop a project from the unsigned directory file.
    Remove {
        id: String,
        #[arg(long, default_value = "projects.unsigned.json")]
        file: PathBuf,
    },
    /// Maintainers: sign the directory file with the maintainers' key into the file runners read.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "projects.unsigned.json")]
        file: PathBuf,
        /// Default: `projects.json` next to the input.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ProjectsCmd {
    /// Support a project: reads its `.devcontainer/devcontainer.json` and agent directory from
    /// GitHub, pulls or prebuilds its environment, shows everything you are approving and, after
    /// you confirm, trusts its key, gives it a share and adds its queue to your config.
    Add {
        /// A project name from the directory (`toto directory list`), or `owner/name` on GitHub.
        repo: String,
        /// Relative weight against your other projects.
        #[arg(long, default_value_t = 1)]
        share: u32,
        /// File with your GitHub token (it only needs to comment on issues).
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long, default_value = toto::github_queue::DEFAULT_API)]
        api: String,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Read everything a project asks you to approve, without changing anything.
    Inspect {
        /// `owner/name`
        repo: String,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long, default_value = toto::github_queue::DEFAULT_API)]
        api: String,
    },
    /// Re-check a project: if its environment or agent directory changed, show what changed and,
    /// after you confirm, approve the new version. Until then tasks keep running what you approved.
    Update {
        id: String,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long, default_value = toto::github_queue::DEFAULT_API)]
        api: String,
        #[arg(long)]
        yes: bool,
    },
    /// Show the projects you support.
    List,
    /// Stop supporting a project.
    Remove { id: String },
}

fn save_config(path: &std::path::Path, cfg: &toto::config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(cfg)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

/// Asks the contributor; `yes` answers for them, and without a terminal there is nobody to ask.
fn confirm(question: &str, yes: bool) -> Result<bool, Box<dyn std::error::Error>> {
    use std::io::{BufRead, IsTerminal, Write};
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err("not a terminal: re-run with --yes to confirm".into());
    }
    print!("\n{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

fn github(api: &str, repo: &str, token_file: Option<&std::path::Path>) -> Result<toto::github_queue::GitHubQueue, Box<dyn std::error::Error>> {
    let token = token_file.map(toto::secrets::read_secret).transpose()?;
    Ok(toto::github_queue::GitHubQueue::new(api, repo, toto::github_queue::DEFAULT_LABEL, token))
}

/// Pulls or prebuilds the project's environment and assembles the approval the contributor is shown.
fn approval_for(cfg: &toto::config::Config, repo: &str, f: &toto::projects::Fetched) -> Result<toto::projects::Approval, Box<dyn std::error::Error>> {
    let bin = cfg.docker_bin().ok_or("project environments are container images: configure a docker or podman sandbox first")?;
    let (image, info, prebuilt) = match &f.devcontainer.image {
        Some(image) => (image.clone(), toto::image::inspect(bin, image, true)?, false),
        None => {
            let network = cfg.sandbox_network().ok_or("this project publishes no image, so it has to be prebuilt here, and a prebuild needs the fenced network: run `toto net-setup --apply` and set `network` in the sandbox config")?;
            let pb = toto::prebuild::Prebuild { bin: bin.into(), cli: toto::prebuild::DEFAULT_CLI.into(), network: network.into(), work_dir: cfg.state_dir.join("prebuild") };
            println!("prebuilding {repo} (build, onCreateCommand, updateContentCommand); this can take a while...");
            let (tag, info) = pb.build(&format!("https://github.com/{repo}.git"), f.commit.as_deref(), &f.devcontainer.toto.id, &f.devcontainer_text, toto::devcontainer::PATH)?;
            (tag, info, true)
        }
    };
    Ok(toto::projects::Approval::new(&image, info, &f.agent_files, f.commit.clone(), prebuilt)?)
}

fn today() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

fn load_signing_key(path: &std::path::Path) -> Result<ed25519_dalek::SigningKey, Box<dyn std::error::Error>> {
    let seed: [u8; 32] = hex::decode(fs::read_to_string(path)?.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("the key file must hold 32 bytes of hex (from `toto project-key`)")?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn load_unsigned(file: &std::path::Path) -> Result<toto::directory::Directory, Box<dyn std::error::Error>> {
    if !file.exists() {
        return Ok(toto::directory::Directory::default());
    }
    Ok(toto::directory::Directory::load_unsigned(&fs::read(file)?)?)
}

fn fetch_directory(d: &toto::config::DirectoryConfig) -> Result<toto::directory::Directory, Box<dyn std::error::Error>> {
    let key = toto::directory::parse_key(&d.public_key)?;
    let gh = toto::github_queue::GitHubQueue::new(&d.api_url, &d.repo, toto::github_queue::DEFAULT_LABEL, None);
    Ok(toto::directory::fetch(&gh, &d.path, &key)?)
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
            println!("wrote {}\nrunner id: {id}\nNext: `toto login`, `toto projects add owner/name`, `toto doctor`.", path.display());
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
                    Tick::Paused { until, reason } => {
                        println!("paused: {reason}; until {}", until.format("%H:%M"));
                        break;
                    }
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
            if !cfg!(target_os = "linux") {
                return Err("the network fence is built from Linux iptables rules on the docker host; on macOS and Windows the daemon runs in a VM you cannot add rules to, so projects whose agents need a network, and prebuilds, are not supported there (published images and offline agents work)".into());
            }
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
        Cmd::ProjectKey { out } => {
            let key = if out.exists() {
                load_signing_key(&out)?
            } else {
                let key = toto::manifest::generate_key();
                fs::write(&out, hex::encode(key.to_bytes()))?;
                fs::set_permissions(&out, fs::Permissions::from_mode(0o600))?;
                key
            };
            println!("public key: {}", hex::encode(key.verifying_key().to_bytes()));
        }
        Cmd::Directory { cmd } => match cmd {
            DirectoryCmd::List { config } => {
                let cfg = toto::config::Config::load(&config_path(config))?;
                let d = fetch_directory(&cfg.directory)?;
                println!("directory github:{} ({}), signed by the maintainers' key {}…", cfg.directory.repo, cfg.directory.path, cfg.directory.public_key.chars().take(16).collect::<String>());
                for l in toto::directory::describe(&d) {
                    println!("{l}");
                }
            }
            DirectoryCmd::Add { repo, file, api, token_file } => {
                let gh = github(&api, &repo, token_file.as_deref())?;
                let f = toto::projects::fetch(&gh)?;
                let entry = toto::directory::entry_from(&repo, &f, &today())?;
                let mut d = load_unsigned(&file)?;
                let replaced = d.upsert(entry.clone());
                fs::write(&file, serde_json::to_string_pretty(&d)? + "\n")?;
                println!("{} `{}` ({}, key {}…, kinds {}, harness {}); now sign: toto directory sign --key <maintainers key> --file {}", if replaced { "refreshed" } else { "added" }, entry.id, entry.repo, &entry.public_key[..16], entry.kinds.join(","), entry.harness, file.display());
            }
            DirectoryCmd::Remove { id, file } => {
                let mut d = load_unsigned(&file)?;
                if !d.remove(&id) {
                    return Err(format!("`{id}` is not in {}", file.display()).into());
                }
                fs::write(&file, serde_json::to_string_pretty(&d)? + "\n")?;
                println!("removed `{id}`; now sign the file");
            }
            DirectoryCmd::Sign { key, file, out } => {
                let d = load_unsigned(&file)?;
                let key = load_signing_key(&key)?;
                let env = d.sign(&key, &today())?;
                let out = out.unwrap_or_else(|| file.with_file_name("projects.json"));
                fs::write(&out, serde_json::to_string_pretty(&env)? + "\n")?;
                // Read it back the way a runner will.
                toto::directory::Directory::open(&fs::read(&out)?, &key.verifying_key())?;
                println!("signed {} projects into {} with key {}…; commit it", d.projects.len(), out.display(), hex::encode(key.verifying_key().to_bytes()).chars().take(16).collect::<String>());
            }
        },
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
        Cmd::Projects { cmd, config } => {
            let path = config_path(config);
            let mut cfg = toto::config::Config::load(&path)?;
            match cmd {
                ProjectsCmd::List => {
                    let lines = toto::projects::list(&cfg);
                    if lines.is_empty() {
                        println!("no projects yet: `toto projects add owner/name`");
                    }
                    for l in lines {
                        println!("{l}");
                    }
                }
                ProjectsCmd::Remove { id } => {
                    println!("{}", toto::projects::remove(&mut cfg, &id)?);
                    save_config(&path, &cfg)?;
                }
                ProjectsCmd::Inspect { repo, token_file, api } => {
                    let gh = github(&api, &repo, token_file.as_deref())?;
                    let f = toto::projects::fetch(&gh)?;
                    let t = &f.devcontainer.toto;
                    println!("{} ({}), from github:{repo} at {}\n{}\n", t.name, t.id, f.commit.as_deref().unwrap_or("?"), t.description);
                    println!("key fingerprint {}, kinds {}\n", t.public_key.chars().take(16).collect::<String>(), t.kinds.join(", "));
                    println!("{}:\n{}", toto::devcontainer::PATH, f.devcontainer_text.trim_end());
                    for n in &f.devcontainer.notes {
                        println!("  note: {n}");
                    }
                    println!("\nagent directory {} ({} files):", f.agent_dir, f.agent_files.len());
                    match toto::agent::summarize(&f.agent_files) {
                        Ok(s) => {
                            for l in s.describe() {
                                println!("  {l}");
                            }
                        }
                        Err(e) => println!("  cannot be run: {e}"),
                    }
                    if let Some(text) = f.agent_files.get("config.yaml") {
                        println!("\nconfig.yaml:\n{}", String::from_utf8_lossy(text).trim_end());
                    }
                    match &f.devcontainer.image {
                        Some(image) => {
                            let bin = cfg.docker_bin().ok_or("configure a docker or podman sandbox first")?;
                            let info = toto::image::inspect(bin, image, true)?;
                            println!("\nthe image itself:");
                            for l in toto::image::describe(image, &info) {
                                println!("  {l}");
                            }
                        }
                        None => println!("\nno published image: `toto projects add` prebuilds it here from the devcontainer config above"),
                    }
                }
                ProjectsCmd::Update { id, token_file, api, yes } => {
                    let repo = cfg.sources.get(&id).cloned().ok_or_else(|| format!("project `{id}` was not added with `toto projects add`"))?;
                    let gh = github(&api, &repo, token_file.as_deref())?;
                    let f = toto::projects::fetch(&gh)?;
                    if cfg.projects.get(&id) != Some(&f.devcontainer.toto.public_key) {
                        return Err(format!("{repo} now publishes a different key for `{id}`: if you trust the change, `toto projects remove {id}` and add it again").into());
                    }
                    let old = cfg.environments.get(&id).cloned();
                    if let Some(old) = &old
                        && old.prebuilt && old.commit.is_some() && old.commit == f.commit
                    {
                        println!("{id}: up to date (commit {})", old.commit.as_deref().unwrap_or(""));
                        return Ok(());
                    }
                    let new = approval_for(&cfg, &repo, &f)?;
                    match old {
                        Some(old) if old.info.id == new.info.id && old.agent_hash == new.agent_hash => println!("{id}: up to date ({})", new.info.short()),
                        old => {
                            println!("{id}: changed since you approved it");
                            let lines = match &old {
                                Some(old) => old.diff(&new),
                                None => new.describe(),
                            };
                            for l in lines {
                                println!("  {l}");
                            }
                            if !confirm("Approve this version?", yes)? {
                                println!("nothing changed; tasks keep running what you approved");
                                return Ok(());
                            }
                            cfg.environments.insert(id.clone(), new);
                            save_config(&path, &cfg)?;
                            println!("approved");
                        }
                    }
                }
                ProjectsCmd::Add { repo: arg, share, token_file, api, yes } => {
                    // A name is looked up in the signed directory; `owner/name` is used as is but
                    // still cross-checked against the directory when it is listed there.
                    let listed = match fetch_directory(&cfg.directory) {
                        Ok(d) => d.resolve(&arg).cloned(),
                        Err(e) if arg.contains('/') => {
                            println!("note: the project directory could not be checked ({e})");
                            None
                        }
                        Err(e) => return Err(format!("`{arg}` is not `owner/name`, and the project directory could not be read to look it up: {e}").into()),
                    };
                    let repo = match (&listed, arg.contains('/')) {
                        (Some(e), _) => e.repo.clone(),
                        (None, true) => arg.clone(),
                        (None, false) => return Err(format!("no project `{arg}` in the directory (`toto directory list` shows them; or give `owner/name`)").into()),
                    };
                    let gh = github(&api, &repo, token_file.as_deref())?;
                    let f = toto::projects::fetch(&gh)?;
                    let t = &f.devcontainer.toto;
                    if let Some(e) = &listed {
                        toto::directory::check_key(e, t)?;
                    }
                    println!("{} ({}), from github:{repo}\n{}\n", t.name, t.id, t.description);
                    match &listed {
                        Some(_) => println!("  key fingerprint  {} (matches the signed directory)", t.public_key.chars().take(16).collect::<String>()),
                        None => println!("  key fingerprint  {} (not in the directory: compare it with what the project publishes)", t.public_key.chars().take(16).collect::<String>()),
                    }
                    println!("  task kinds       {}", t.kinds.join(", "));
                    println!("  share            {}", share.max(1));
                    for n in &f.devcontainer.notes {
                        println!("  note: {n}");
                    }
                    let approval = approval_for(&cfg, &repo, &f)?;
                    let opts = toto::projects::AddOptions { share, token_file };
                    let mut updated = cfg.clone();
                    let notes = toto::projects::add(&mut updated, &repo, &f.devcontainer, approval.clone(), &opts)?;
                    println!("\nwhat you are approving:");
                    for l in approval.describe() {
                        println!("  {l}");
                    }
                    for n in &notes {
                        println!("  {n}");
                    }
                    println!("\n(`toto projects inspect {repo}` shows the files themselves)");
                    if !confirm("Support this project and approve this environment and agent?", yes)? {
                        println!("nothing changed");
                        return Ok(());
                    }
                    save_config(&path, &updated)?;
                    println!("\nadded; run `toto doctor` to check the setup");
                }
            }
        }
        Cmd::ResultsToPr { repo, repo_dir, base, projects, token_file, api, max_open, protect } => {
            let token = match &token_file {
                Some(f) => toto::secrets::read_secret(f)?,
                None => std::env::var("GITHUB_TOKEN").map_err(|_| "no token: pass --token-file or set GITHUB_TOKEN")?,
            };
            let mut trusted = toto::manifest::TrustedProjects::default();
            for p in &projects {
                let (id, key) = p.split_once('=').ok_or("--project needs `id=<hex public key>`")?;
                let bytes: [u8; 32] = hex::decode(key).ok().and_then(|b| b.try_into().ok()).ok_or("project key must be 32 bytes of hex")?;
                trusted.insert(id, ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| "bad project key")?);
            }
            let q = toto::github_queue::GitHubQueue::new(&api, &repo, toto::github_queue::DEFAULT_LABEL, Some(token));
            let mut opts = toto::pr_flow::Options::new(repo_dir, &base);
            opts.max_open = max_open;
            opts.protected.extend(protect);
            for o in toto::pr_flow::run(&q, &repo, &trusted, &opts)? {
                println!("{o:?}");
            }
        }
        Cmd::GithubResults { repo, token_file, api, out } => {
            let q = github(&api, &repo, token_file.as_deref())?;
            fs::create_dir_all(&out)?;
            let results = q.results()?;
            for r in &results {
                let b = r.open()?;
                let path = out.join(format!("{}.{}.json", b.task_id, &b.runner_id[..16]));
                fs::write(&path, serde_json::to_vec_pretty(r)?)?;
                println!("{} ({} tokens)", path.display(), b.tokens_used);
            }
            println!("{} results", results.len());
        }
        Cmd::PostTask { key, config, bundle, task, github: gh_repo, github_token_file, github_api } => {
            let cfg = toto::config::Config::load(&config_path(config))?;
            let seed: [u8; 32] = hex::decode(fs::read_to_string(&key)?.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("project key must be a 32-byte hex seed")?;
            let mut manifest: TaskManifest = serde_json::from_slice(&fs::read(&task)?)?;
            let gh = match &gh_repo {
                Some(repo) => Some(github(&github_api, repo, github_token_file.as_deref())?),
                None => None,
            };
            let spool = toto::queue::DirQueue::new(&cfg.queue_dir)?;
            if let Some(dir) = bundle {
                let records = toto::archive::pack_dir(&dir, toto::archive::Limits::new(cfg.policy.max_input_bytes))?;
                let bytes = toto::archive::to_bytes(&records)?;
                manifest.inputs = match &gh {
                    Some(g) => g.upload_bundle(&bytes)?,
                    None => spool.post_bundle(&bytes)?,
                };
                println!("bundled {} files from {} as {}", records.len(), dir.display(), manifest.inputs);
            }
            let signed = manifest.sign(&ed25519_dalek::SigningKey::from_bytes(&seed))?;
            match (&gh, &gh_repo) {
                (Some(g), Some(repo)) => println!("posted {} as issue #{} in {repo}", manifest.id, g.post_task(&signed)?),
                _ => {
                    spool.post(&signed)?;
                    println!("posted {} to {}", manifest.id, cfg.queue_dir.display());
                }
            }
        }
        Cmd::Login { config } => {
            let cfg = toto::config::Config::load(&config_path(config))?;
            let token_file = match &cfg.harness {
                toto::config::HarnessConfig::Omnigent { provider: toto::config::ProviderConfig::Anthropic, token_file, .. } => token_file.clone().unwrap_or_else(|| cfg.token_path()),
                _ => return Err("login is for the Anthropic subscription; set harness.provider to anthropic (for openai, point api_key_file at a key file)".into()),
            };
            fs::create_dir_all(&cfg.state_dir)?;
            println!("Running `claude setup-token`. Complete the browser sign-in, then paste the token it prints.");
            std::process::Command::new("claude").arg("setup-token").status()?;
            let token = rpassword::prompt_password("Paste token (input hidden): ")?;
            if token.trim().is_empty() {
                return Err("no token entered".into());
            }
            toto::secrets::save_token(&token_file, &token)?;
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
        max_input_bytes: 64 * 1024 * 1024,
        reserve_pct: 20,
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
