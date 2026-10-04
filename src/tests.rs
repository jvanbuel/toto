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
