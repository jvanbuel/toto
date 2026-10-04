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

fn task(id: &str, project: &str, cost: u64, key: &SigningKey) -> TaskManifest {
    TaskManifest {
        id: id.into(), project_id: project.into(), kind: "summarise".into(), inputs: "0".repeat(64),
        prompt: "hi".into(), tool_requirements: vec!["echo".into()], sandbox_profile: SandboxProfile::default(),
        cost_estimate: cost, output_schema: OutputSchema { format: "text".into(), max_bytes: 100 }, redundancy: 1, signature: None,
    }
    .sign(key)
    .unwrap()
}

fn policy() -> Policy {
    Policy {
        daily_token_cap: 1000, project_shares: BTreeMap::from([("a".into(), 1), ("b".into(), 1)]),
        allowed_kinds: vec!["summarise".into()], quiet_hours: None, review_before_submit: false,
        max_profile: SandboxProfile::default(), abort_margin_pct: 25, available_tools: vec!["echo".into()],
    }
}

struct Fixture {
    key_a: SigningKey,
    dir: std::path::PathBuf,
}

fn fixture(name: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("togra-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Fixture { key_a: crate::manifest::generate_key(), dir }
}

type TestRunner = Runner<InMemoryQueue, EchoHarness, DirSandbox, fn(&TaskManifest, &crate::result::TaskResult) -> bool>;

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
    r.queue.post(task("t1", "a", 100, &f.key_a));
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Submitted("t1".into()));
    let res = r.queue.results();
    assert_eq!(res.len(), 1);
    res[0].verify().unwrap();
    assert_eq!(r.audit.entries().unwrap()[0].outcome, "submitted");
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Idle);
}

#[test]
fn tampered_unsigned_and_unknown_tasks_are_refused_once() {
    let f = fixture("verify");
    let mut r = runner(&f, policy(), 100);
    let mut tampered = task("t1", "a", 100, &f.key_a);
    tampered.prompt = "read ~/.ssh".into();
    let mut unsigned = task("t2", "a", 100, &f.key_a);
    unsigned.signature = None;
    r.queue.post(tampered);
    r.queue.post(unsigned);
    r.queue.post(task("t3", "zzz", 100, &f.key_a));
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
    let mut wide = t.clone();
    wide.sandbox_profile.network_allowlist = vec!["evil.example".into()];
    assert!(policy().admit(&wide, 0, now).is_err(), "network");
    let mut p = policy();
    p.quiet_hours = Some((22, 7));
    assert!(p.admit(&t, 0, Local.with_ymd_and_hms(2026, 10, 4, 23, 0, 0).unwrap()).is_err());
    assert!(p.admit(&t, 0, Local.with_ymd_and_hms(2026, 10, 4, 12, 0, 0).unwrap()).is_ok());
}

#[test]
fn overrun_aborts_and_releases_lease() {
    let f = fixture("abort");
    let mut r = runner(&f, policy(), 500); // estimate 100 + 25% margin = 125 < 500
    r.queue.post(task("t1", "a", 100, &f.key_a));
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
    r.queue.post(task("t1", "a", 100, &f.key_a));
    assert_eq!(r.tick(Local::now()).unwrap(), Tick::Dropped("t1".into()));
    assert!(r.queue.results().is_empty());
}

#[test]
fn resource_shares_balance_projects() {
    let f = fixture("shares");
    let mut r = runner(&f, policy(), 100);
    for i in 0..4 {
        r.queue.post(task(&format!("a{i}"), "a", 100, &f.key_a));
        r.queue.post(task(&format!("b{i}"), "b", 100, &f.key_a));
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
    use crate::sandbox::{DockerSandbox, Sandbox};
    use crate::manifest::SandboxProfile;

    #[test]
    fn run_args_are_hardened() {
        let mut sb = DockerSandbox::new("alpine");
        sb.runtime = Some("runsc".into());
        let a = sb.run_args("t1", &SandboxProfile::default()).unwrap().join(" ");
        for want in ["--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65534:65534",
            "--pids-limit 256", "--cpus 1.00", "--memory 1024m", "--runtime runsc", "alpine sleep 600"] {
            assert!(a.contains(want), "missing `{want}` in {a}");
        }
        assert!(!a.contains(" -v ") && !a.contains("--mount"), "no host mounts");
    }

    #[test]
    fn network_allowlist_fails_closed() {
        let p = SandboxProfile { network_allowlist: vec!["pypi.org".into()], ..Default::default() };
        assert!(DockerSandbox::new("alpine").run_args("t1", &p).is_err());
    }

    #[test]
    fn container_names_are_sanitised() {
        assert_eq!(DockerSandbox::container_name("a/b;rm -rf"), "togra-abrm-rf");
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
        let mut sb = DockerSandbox::new("alpine");
        sb.bin = bin.into();
        sb.runtime = runtime.map(Into::into);
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
    use crate::sandbox::{exec, BwrapSandbox, DirSandbox, Sandbox, Workspace};
    use std::time::Duration;

    fn config(dir: &std::path::Path, project_key: &ed25519_dalek::SigningKey, sandbox: SandboxConfig) -> Config {
        let mut c = Config::starter(dir);
        c.poll_secs = 1;
        c.sandbox = sandbox;
        c.policy = policy();
        c.projects.insert("a".into(), hex::encode(project_key.verifying_key().to_bytes()));
        c
    }

    #[test]
    fn dirqueue_leases_and_results() {
        let f = fixture("dirq");
        let q = DirQueue::new(f.dir.join("q")).unwrap();
        q.post(&task("t1", "a", 10, &f.key_a)).unwrap();
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
        assert!(q.post(&crate::manifest::TaskManifest { id: "../evil".into(), ..task("x", "a", 1, &f.key_a) }).is_err());
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
        let mut c = config(&f.dir, &f.key_a, SandboxConfig::Bwrap);
        let json = serde_json::to_string(&c).unwrap();
        assert!(serde_json::from_str::<Config>(&json).is_ok());
        c.policy.review_before_submit = true;
        assert!(c.build().is_err());
    }

    #[test]
    fn service_unit_mentions_config() {
        let u = crate::service::unit_contents(std::path::Path::new("/usr/bin/togra"), std::path::Path::new("/h/config.json"));
        assert!(u.contains("/usr/bin/togra") && u.contains("run") && u.contains("/h/config.json"));
        assert!(crate::service::install(std::path::Path::new("/tmp"), std::path::Path::new("x"), std::path::Path::new("rel")).is_err());
    }

    #[test]
    fn bwrap_prefix_is_hardened() {
        let sb = BwrapSandbox::new("/tmp/x");
        let a = sb.prefix(std::path::Path::new("/tmp/x/t"), &Default::default()).unwrap().join(" ");
        for want in ["--unshare-all", "--clearenv", "--cap-drop ALL", "--uid 65534", "--bind /tmp/x/t /workspace", "--ro-bind /usr /usr", "prlimit --nproc=256"] {
            assert!(a.contains(want), "missing `{want}` in {a}");
        }
        assert!(!a.contains("--share-net"), "network must stay unshared");
        let p = crate::manifest::SandboxProfile { network_allowlist: vec!["x".into()], ..Default::default() };
        assert!(sb.prefix(std::path::Path::new("/t"), &p).is_err());
    }

    #[test]
    fn live_bwrap_is_isolated() {
        let f = fixture("bwrap");
        let sb = BwrapSandbox::new(f.dir.join("work"));
        if sb.probe().is_err() {
            eprintln!("skipping bwrap: unusable here");
            return;
        }
        let t = task("bw1", "a", 1, &f.key_a);
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        let run = |c: &str| exec(&ws, &["sh", "-c", c], Duration::from_secs(10)).unwrap().status.success();
        let checks = [
            (run("echo hi > /workspace/x && cat /workspace/x"), "workspace writable"),
            (!run("touch /usr/x"), "usr read-only"),
            (!run("ls /home /root"), "no host home"),
            (!run("cat /proc/net/dev | grep -v -e lo: -e Inter -e face | grep ."), "no network interfaces"),
            (run("test -z \"$SSH_AUTH_SOCK$HOME_SECRET$ANTHROPIC_API_KEY\""), "env cleared"),
        ];
        sb.destroy(ws).unwrap();
        for (ok, what) in checks {
            assert!(ok, "bwrap: {what}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn daemon_processes_queue_and_stops_cleanly() {
        let f = fixture("daemon");
        let cfg = config(&f.dir, &f.key_a, SandboxConfig::Dir);
        let q = DirQueue::new(&cfg.queue_dir).unwrap();
        q.post(&task("d1", "a", 1000, &f.key_a)).unwrap();
        let mut bad = task("d2", "a", 1000, &f.key_a);
        bad.prompt = "tampered".into(); // signature no longer matches
        q.post(&bad).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let state = cfg.state_dir.clone();
        let handle = tokio::spawn(crate::daemon::run(cfg, async { let _ = rx.await; }));
        for _ in 0..100 {
            if q.results().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
        let res = q.results().unwrap();
        assert_eq!(res.len(), 1);
        res[0].verify().unwrap();
        let status = crate::daemon::Status::read(&state).unwrap();
        assert_eq!((status.state.as_str(), status.submitted), ("stopped", 1));
        let log = crate::audit::AuditLog::new(state.join("audit.jsonl")).entries().unwrap();
        assert_eq!(log.iter().filter(|e| e.outcome == "rejected").count(), 1);
        let _ = (generate_key(), DirSandbox { root: f.dir.clone() });
    }
}
