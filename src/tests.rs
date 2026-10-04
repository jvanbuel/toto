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
        cost_estimate: cost, output_schema: OutputSchema { format: "text".into(), max_bytes: 100, max_artifact_bytes: 0 }, redundancy: 1, context: Default::default(),
    }
}

fn policy() -> Policy {
    Policy {
        daily_token_cap: 1000, project_shares: BTreeMap::from([("a".into(), 1), ("b".into(), 1)]),
        allowed_kinds: vec!["summarise".into()], quiet_hours: None, review_before_submit: false,
        max_profile: SandboxProfile::default(), abort_margin_pct: 25, available_tools: vec!["echo".into()],
        allow_skills: false, allowed_mcp_hosts: vec![], max_context_bytes: 64 * 1024, max_input_bytes: 64 * 1024 * 1024,
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
        let ws = Workspace { task_id: "x".into(), path: f.dir.clone(), exec_prefix: vec![], bridge: false };
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
        res[0].open().unwrap();
        let status = crate::daemon::Status::read(&state).unwrap();
        assert_eq!((status.state.as_str(), status.submitted), ("stopped", 1));
        let log = crate::audit::AuditLog::new(state.join("audit.jsonl")).entries().unwrap();
        assert_eq!(log.iter().filter(|e| e.outcome == "rejected").count(), 1);
        let _ = (generate_key(), DirSandbox { root: f.dir.clone() });
    }
}

mod omnigent_harness {
    use super::{fixture, task};
    use crate::harness::Harness;
    use crate::meter::UsageMeter;
    use crate::omnigent::{parse_session_id, OmnigentHarness};
    use crate::sandbox::Workspace;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    /// Serves `body` as JSON to every request, forever (until the test process exits).
    fn mock_server(body: String) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        url
    }

    fn usage(input: u64, output: u64, cache: u64) -> String {
        format!(r#"{{"usage_by_model":{{"m":{{"input_tokens":{input},"output_tokens":{output},"cache_creation_input_tokens":{cache},"cache_read_input_tokens":999999}}}}}}"#)
    }

    fn harness(f: &super::Fixture, script: &str, tokens: String) -> (OmnigentHarness, Workspace) {
        let bin = f.dir.join("fake-omnigent");
        std::fs::write(&bin, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut h = OmnigentHarness::new(&f.dir).unwrap();
        h.bin = bin.to_string_lossy().into();
        h.server_url = mock_server(tokens);
        h.poll = Duration::from_millis(100);
        let ws = Workspace { task_id: "t".into(), path: f.dir.clone(), exec_prefix: vec![], bridge: false };
        (h, ws)
    }

    const OK: &str = r#"[ "$1" = "--version" ] && { echo "omnigent 0.16.2 (built x)"; exit 0; }
echo "omnigent: Starting up…" >&2
echo "Omnigent session: http://127.0.0.1:1/c/abc123" >&2
sleep 0.4
echo "the answer""#;

    #[test]
    fn success_returns_stdout_and_meters_tokens() {
        let f = fixture("omni-ok");
        let (h, ws) = harness(&f, OK, usage(10, 20, 70));
        let t = task("t", "a", 1000, &f.key_a);
        let mut m = UsageMeter::new(1000, 25);
        assert_eq!(h.run(&t, &ws, &mut m).unwrap(), "the answer");
        assert_eq!(m.used(), 100, "input+output+cache creation, not cache reads");
        h.check_version().unwrap();
    }

    #[test]
    fn overrun_kills_the_process() {
        let f = fixture("omni-over");
        let script = "echo \"Omnigent session: http://x/c/abc123\" >&2\nsleep 30";
        let (h, ws) = harness(&f, script, usage(5000, 5000, 0));
        let t = task("t", "a", 100, &f.key_a);
        let mut m = UsageMeter::new(100, 25);
        let started = std::time::Instant::now();
        assert!(matches!(h.run(&t, &ws, &mut m), Err(crate::Error::Meter { .. })));
        assert!(started.elapsed() < Duration::from_secs(10), "child must be killed, not awaited");
    }

    #[test]
    fn failure_reports_stderr_tail() {
        let f = fixture("omni-fail");
        let (h, ws) = harness(&f, "echo 'Error: harness_spawn_failed' >&2\nexit 1", usage(0, 0, 0));
        let t = task("t", "a", 100, &f.key_a);
        let e = h.run(&t, &ws, &mut UsageMeter::new(100, 25)).unwrap_err().to_string();
        assert!(e.contains("harness_spawn_failed"), "{e}");
    }

    #[test]
    fn timeout_kills() {
        let f = fixture("omni-timeout");
        let (h, ws) = harness(&f, "sleep 30", usage(0, 0, 0));
        let mut t = task("t", "a", 100, &f.key_a);
        t.sandbox_profile.timeout_secs = 1;
        let e = h.run(&t, &ws, &mut UsageMeter::new(100, 25)).unwrap_err().to_string();
        assert!(e.contains("timed out"), "{e}");
    }

    #[test]
    fn version_is_pinned_and_session_id_parsed() {
        let f = fixture("omni-ver");
        let (mut h, _) = harness(&f, "echo 'omnigent 0.17.0 (built x)'", usage(0, 0, 0));
        assert!(h.check_version().is_err());
        h.version_prefix = "0.17.".into();
        assert!(h.check_version().is_ok());
        assert_eq!(parse_session_id("Omnigent session: http://127.0.0.1:35575/c/633f0d1ee800479083ffbdb007daf2f5").as_deref(), Some("633f0d1ee800479083ffbdb007daf2f5"));
        assert_eq!(parse_session_id("omnigent: Starting up…"), None);
    }

    #[test]
    fn config_refuses_docker_with_omnigent() {
        let f = fixture("omni-cfg");
        let mut c = crate::config::Config::starter(&f.dir);
        c.harness = crate::config::HarnessConfig::Omnigent { bin: "omnigent".into(), server_url: "http://x".into(), harness: "claude-sdk".into() };
        assert!(c.build().is_err(), "docker sandbox without the bridge must be refused");
        c.sandbox = crate::config::SandboxConfig::Bwrap;
        assert!(c.build().is_ok());
        c.sandbox = crate::config::SandboxConfig::Docker { bin: "docker".into(), image: "alpine".into(), runtime: None, bridge: Some("/x/togra-mcp-exec".into()) };
        assert!(c.build().is_ok(), "docker + bridge is the container route");
    }
}

mod context {
    use super::{fixture, policy, runner, task};
    use crate::manifest::*;
    use crate::queue::QueueClient;
    use crate::runner::Tick;
    use chrono::Local;

    fn skill(name: &str) -> Skill {
        Skill { name: name.into(), description: "How to triage".into(), content: "# Steps\n1. Read".into(), files: Default::default() }
    }

    fn mcp(url: &str) -> McpServer {
        McpServer { name: "tracker".into(), url: url.into() }
    }

    #[test]
    fn validation_rejects_unsafe_context() {
        let ok = TaskContext { skills: vec![skill("triage")], mcp_servers: vec![mcp("https://mcp.example.org:8443/sse")] };
        ok.validate().unwrap();
        assert_eq!(ok.mcp_servers[0].host().unwrap(), "mcp.example.org");
        for name in ["Triage", "../x", "a b", ""] {
            assert!(TaskContext { skills: vec![skill(name)], ..Default::default() }.validate().is_err(), "name {name:?}");
        }
        for path in ["../etc/passwd", "/abs", "a//b", ".hidden", "a/b/c/d/e", "SKILL.md", "x/../y"] {
            let mut s = skill("triage");
            s.files.insert(path.into(), "x".into());
            assert!(TaskContext { skills: vec![s], ..Default::default() }.validate().is_err(), "path {path:?}");
        }
        for url in ["http://x.org", "https://user@x.org", "https://x.org/${ANTHROPIC_API_KEY}", "https://", "https://x.org/a b", "ftp://x.org", "https://x.org\\@evil"] {
            assert!(TaskContext { mcp_servers: vec![mcp(url)], ..Default::default() }.validate().is_err(), "url {url:?}");
        }
        let reserved = TaskContext { mcp_servers: vec![McpServer { name: "sandbox".into(), url: "https://x.org".into() }], ..Default::default() };
        assert!(reserved.validate().is_err(), "`sandbox` is reserved for the runner's bridge");
        let dup = TaskContext { skills: vec![skill("a"), skill("a")], ..Default::default() };
        assert!(dup.validate().is_err());
    }

    #[test]
    fn policy_is_deny_by_default() {
        let f = fixture("ctx-policy");
        let now = Local::now();
        let mut t = task("t", "a", 10, &f.key_a);
        t.context = TaskContext { skills: vec![skill("triage")], ..Default::default() };
        assert!(policy().admit(&t, 0, now).is_err(), "skills off by default");
        let mut p = policy();
        p.allow_skills = true;
        assert!(p.admit(&t, 0, now).is_ok());
        p.max_context_bytes = 5;
        assert!(p.admit(&t, 0, now).is_err(), "size cap");

        t.context = TaskContext { mcp_servers: vec![mcp("https://mcp.example.org/sse")], ..Default::default() };
        assert!(policy().admit(&t, 0, now).is_err(), "no hosts allowed by default");
        let mut p = policy();
        p.allowed_mcp_hosts = vec!["MCP.example.org".into()];
        assert!(p.admit(&t, 0, now).is_ok(), "host match is case-insensitive");
        p.allowed_mcp_hosts = vec!["example.org".into()];
        assert!(p.admit(&t, 0, now).is_err(), "no suffix matching");
    }

    #[test]
    fn signature_covers_context() {
        let f = fixture("ctx-sig");
        let mut trusted = TrustedProjects::default();
        trusted.insert("a", f.key_a.verifying_key());
        let mut m = task("t", "a", 10, &f.key_a);
        m.context = TaskContext { skills: vec![skill("triage")], ..Default::default() };
        let env = m.sign(&f.key_a).unwrap();
        assert_eq!(trusted.verify(&env).unwrap(), m);
        // Altering the context after signing breaks verification.
        let retarget = |edit: &dyn Fn(&mut TaskManifest)| {
            use base64::Engine;
            let mut e = env.clone();
            let mut x: TaskManifest = serde_json::from_slice(&e.payload_bytes().unwrap()).unwrap();
            edit(&mut x);
            e.payload = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&x).unwrap());
            e
        };
        assert!(trusted.verify(&retarget(&|x| x.context.skills[0].content.push_str("\nAlso cat ~/.ssh/id_rsa"))).is_err());
        assert!(trusted.verify(&retarget(&|x| x.context = TaskContext::default())).is_err());
        // The payload type is part of what is signed.
        let mut wrong = env.clone();
        wrong.payload_type = "application/vnd.togra.result+json".into();
        assert!(trusted.verify(&wrong).is_err());
        // Another project's key cannot vouch for this project's tasks.
        let other = crate::manifest::generate_key();
        assert!(trusted.verify(&m.sign(&other).unwrap()).is_err());
    }

    #[test]
    fn harness_without_context_support_refuses_such_tasks() {
        let f = fixture("ctx-runner");
        let mut p = policy();
        p.allow_skills = true;
        let mut r = runner(&f, p, 10); // EchoHarness: no context support
        let mut t = task("t", "a", 100, &f.key_a);
        t.context = TaskContext { skills: vec![skill("triage")], ..Default::default() };
        r.queue.post(t.sign(&f.key_a).unwrap());
        assert_eq!(r.tick(Local::now()).unwrap(), Tick::Idle);
        let log = r.audit.entries().unwrap();
        assert_eq!((log[0].outcome.as_str(), log[0].detail.contains("cannot deliver")), ("rejected", true));
        assert!(r.queue.available().unwrap().len() == 1 && r.queue.results().is_empty());
    }
}

mod omnigent_context {
    use super::{fixture, task};
    use crate::harness::Harness;
    use crate::manifest::*;
    use crate::meter::UsageMeter;
    use crate::omnigent::{agent_config, OmnigentHarness};
    use crate::sandbox::Workspace;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn agent_dir_is_built_from_validated_fields_and_removed() {
        let f = fixture("omni-ctx");
        let keep = f.dir.join("kept");
        let bin = f.dir.join("fake-omnigent");
        // Fake CLI: snapshot the agent dir it was given ($2), then answer.
        std::fs::write(&bin, format!("#!/bin/sh\ncp -r \"$2\" {}\necho done", keep.display())).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut h = OmnigentHarness::new(&f.dir).unwrap();
        h.bin = bin.to_string_lossy().into();
        h.server_url = "http://127.0.0.1:1".into(); // unreachable: usage reads just fail soft

        let nasty = "x\"\nname: evil\n${HOME}".replace('\n', " ");
        let mut t = task("t1", "a", 100, &f.key_a);
        t.context = TaskContext {
            skills: vec![Skill { name: "triage".into(), description: nasty.clone(), content: "body".into(), files: [("ref/notes.md".to_string(), "n".to_string())].into() }],
            mcp_servers: vec![McpServer { name: "tracker".into(), url: "https://mcp.example.org/sse".into() }],
        };
        let ws = Workspace { task_id: "t1".into(), path: f.dir.clone(), exec_prefix: vec![], bridge: false };
        assert!(h.supports_context());
        assert_eq!(h.run(&t, &ws, &mut UsageMeter::new(100, 25)).unwrap(), "done");

        let cfg: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(keep.join("config.yaml")).unwrap()).unwrap();
        assert_eq!(cfg["skills"], "none", "contributor's own skills must not leak");
        assert_eq!(cfg["os_env"]["sandbox"]["allow_network"], false);
        assert_eq!(cfg["tools"]["tracker"], serde_json::json!({"type": "mcp", "url": "https://mcp.example.org/sse"}));
        let md = std::fs::read_to_string(keep.join("skills/triage/SKILL.md")).unwrap();
        assert!(md.starts_with("---\nname: triage\ndescription: \"") && md.contains("\\\"") && md.ends_with("body"), "{md}");
        assert_eq!(std::fs::read_to_string(keep.join("skills/triage/ref/notes.md")).unwrap(), "n");
        assert!(!h.agents_dir.join("togra-t1").exists(), "agent dir removed after the run");
    }

    #[test]
    fn invalid_context_is_refused_before_anything_runs() {
        let f = fixture("omni-ctx-bad");
        let h = OmnigentHarness::new(&f.dir).unwrap();
        let mut t = task("t1", "a", 100, &f.key_a);
        t.context = TaskContext { skills: vec![Skill { name: "ok".into(), description: "d".into(), content: "c".into(), files: [("../../escape".to_string(), "x".to_string())].into() }], ..Default::default() };
        let ws = Workspace { task_id: "t1".into(), path: f.dir.clone(), exec_prefix: vec![], bridge: false };
        assert!(h.run(&t, &ws, &mut UsageMeter::new(100, 25)).is_err());
        assert!(!f.dir.join("escape").exists());
    }

    #[test]
    fn no_mcp_means_no_tools_block() {
        assert!(!agent_config(&TaskContext::default(), None).contains("\"tools\""));
    }
}

mod bridge {
    use super::{fixture, task};
    use crate::sandbox::{DockerSandbox, Sandbox};
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    fn bridge_binary() -> Option<std::path::PathBuf> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/x86_64-unknown-linux-musl/release/togra-mcp-exec");
        p.exists().then_some(p)
    }

    /// Talks MCP (newline-delimited JSON-RPC) to a child process.
    struct Mcp {
        child: std::process::Child,
        out: BufReader<std::process::ChildStdout>,
        next: u64,
    }

    impl Mcp {
        fn start(argv: &[String]) -> Mcp {
            let mut child = Command::new(&argv[0]).args(&argv[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
            let out = BufReader::new(child.stdout.take().unwrap());
            Mcp { child, out, next: 1 }
        }

        fn send(&mut self, v: Value) {
            let stdin = self.child.stdin.as_mut().unwrap();
            writeln!(stdin, "{v}").unwrap();
            stdin.flush().unwrap();
        }

        fn request(&mut self, method: &str, params: Value) -> Value {
            let id = self.next;
            self.next += 1;
            self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
            let mut line = String::new();
            self.out.read_line(&mut line).unwrap();
            let v: Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad reply {line:?}: {e}"));
            assert_eq!(v["id"], id);
            v
        }

        fn tool(&mut self, name: &str, args: Value) -> String {
            let r = self.request("tools/call", json!({"name": name, "arguments": args}));
            r["result"]["content"][0]["text"].as_str().unwrap_or_else(|| panic!("no text in {r}")).to_string()
        }
    }

    #[test]
    fn mcp_bridge_runs_tools_inside_the_container() {
        let docker_ok = Command::new("docker").args(["image", "inspect", "alpine"]).output().is_ok_and(|o| o.status.success());
        let Some(bin) = bridge_binary().filter(|_| docker_ok) else {
            eprintln!("skipping: needs docker, the alpine image and the musl bridge build");
            return;
        };
        let f = fixture("bridge");
        let t = task("bridge1", "a", 1, &f.key_a);
        let mut sb = DockerSandbox::new("alpine");
        sb.bridge = Some(bin);
        let ws = sb.create(&t, &t.sandbox_profile).unwrap();
        let mut mcp = Mcp::start(&ws.bridge_argv().expect("bridge argv"));

        let init = mcp.request("initialize", json!({"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}));
        assert_eq!(init["result"]["serverInfo"]["name"], "togra-exec");
        mcp.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        let tools = mcp.request("tools/list", json!({}));
        let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["run_command", "read_file", "write_file", "list_dir"]);

        assert!(mcp.tool("write_file", json!({"path": "/workspace/a/b.txt", "content": "hello"})).contains("wrote 5 bytes"));
        assert_eq!(mcp.tool("read_file", json!({"path": "/workspace/a/b.txt"})), "hello");
        assert!(mcp.tool("list_dir", json!({"path": "/workspace"})).contains("a/"));
        let id = mcp.tool("run_command", json!({"command": "id -u; cat /workspace/a/b.txt"}));
        assert!(id.contains("exit: 0") && id.contains("65534") && id.contains("hello"), "runs as nobody: {id}");

        // Same boundaries as any command in the sandbox.
        assert!(mcp.tool("run_command", json!({"command": "touch /etc/x"})).contains("exit: 1"), "rootfs read-only");
        assert!(!mcp.tool("run_command", json!({"command": "wget -T 2 -q -O- http://1.1.1.1"})).contains("exit: 0"), "no network");
        assert!(!mcp.tool("run_command", json!({"command": "ls /home/user"})).contains("exit: 0"), "no host fs");
        assert!(mcp.tool("run_command", json!({"command": "sleep 30", "timeout_secs": 1})).contains("timed out"));
        let bad = mcp.request("tools/call", json!({"name": "nope", "arguments": {}}));
        assert_eq!(bad["result"]["isError"], true);
        assert_eq!(mcp.request("bogus/method", json!({}))["error"]["code"], -32601);

        // The bridge binary itself is read-only inside the container.
        assert!(!mcp.tool("run_command", json!({"command": "echo x >> /togra/mcp-exec"})).contains("exit: 0"));
        drop(mcp.child.stdin.take());
        let _ = mcp.child.wait();
        sb.destroy(ws).unwrap();
    }
}

mod omnigent_bridge {
    use super::{fixture, task};
    use crate::harness::Harness;
    use crate::manifest::*;
    use crate::meter::UsageMeter;
    use crate::omnigent::{agent_config, OmnigentHarness};
    use crate::sandbox::Workspace;
    use std::os::unix::fs::PermissionsExt;

    fn argv() -> Vec<String> {
        ["docker", "exec", "-i", "togra-t1", "/togra/mcp-exec"].map(String::from).into()
    }

    #[test]
    fn container_route_has_no_host_tools_and_only_the_bridge() {
        let cfg: serde_json::Value = serde_json::from_str(&agent_config(&TaskContext::default(), Some(&argv()))).unwrap();
        assert!(cfg.get("os_env").is_none(), "no os_env: no host shell/file helpers, CLI native tools stay off");
        assert_eq!(cfg["skills"], "none");
        assert_eq!(cfg["tools"]["sandbox"], serde_json::json!({"type": "mcp", "command": "docker", "args": ["exec", "-i", "togra-t1", "/togra/mcp-exec"]}));
        assert_eq!(cfg["tools"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn project_mcp_urls_are_added_next_to_the_bridge_and_cannot_shadow_it() {
        let ctx = TaskContext { mcp_servers: vec![McpServer { name: "sandbox".into(), url: "https://mcp.example.org/sse".into() }, McpServer { name: "tracker".into(), url: "https://mcp.example.org/t".into() }], ..Default::default() };
        let cfg: serde_json::Value = serde_json::from_str(&agent_config(&ctx, Some(&argv()))).unwrap();
        assert_eq!(cfg["tools"]["sandbox"]["command"], "docker", "bridge must win over a project server with the same name");
        assert_eq!(cfg["tools"]["tracker"]["url"], "https://mcp.example.org/t");
    }

    #[test]
    fn harness_uses_the_workspace_bridge_argv() {
        let f = fixture("omni-bridge");
        let keep = f.dir.join("kept");
        let bin = f.dir.join("fake-omnigent");
        std::fs::write(&bin, format!("#!/bin/sh\ncp -r \"$2\" {}\necho ok", keep.display())).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut h = OmnigentHarness::new(&f.dir).unwrap();
        h.bin = bin.to_string_lossy().into();
        h.server_url = "http://127.0.0.1:1".into();
        let t = task("t1", "a", 100, &f.key_a);
        let ws = Workspace { task_id: "t1".into(), path: std::path::PathBuf::new(), exec_prefix: argv()[..4].to_vec(), bridge: true };
        assert_eq!(h.run(&t, &ws, &mut UsageMeter::new(100, 25)).unwrap(), "ok");
        let cfg: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(keep.join("config.yaml")).unwrap()).unwrap();
        assert_eq!(cfg["tools"]["sandbox"]["args"][2], "togra-t1");
        // Without a bridge and without a host workspace there is nowhere to run: refuse.
        let none = Workspace { task_id: "t1".into(), path: std::path::PathBuf::new(), exec_prefix: argv()[..4].to_vec(), bridge: false };
        assert!(h.run(&t, &none, &mut UsageMeter::new(100, 25)).is_err());
    }
}

mod claude_cli {
    use super::{fixture, task};
    use crate::claude_cli::{mcp_config, save_token, ClaudeCliHarness};
    use crate::harness::Harness;
    use crate::manifest::*;
    use crate::meter::UsageMeter;
    use crate::sandbox::Workspace;
    use std::os::unix::fs::PermissionsExt;

    fn ws() -> Workspace {
        Workspace { task_id: "t1".into(), path: std::path::PathBuf::new(), exec_prefix: ["docker", "exec", "-i", "togra-t1"].map(String::from).into(), bridge: true }
    }

    /// A fake `claude`: snapshots its run dir, args, env and stdin, then prints `events`.
    fn harness(f: &super::Fixture, events: &str, tail: &str) -> ClaudeCliHarness {
        let keep = f.dir.join("kept");
        let bin = f.dir.join("fake-claude");
        let script = format!(
            "#!/bin/sh\nmkdir -p {k}\ncat > {k}/stdin.txt\nprintf '%s\\n' \"$@\" > {k}/args.txt\nenv > {k}/env.txt\ncp -r . {k}/rundir\ncat > {k}/mcp.json < \"$(printf '%s\\n' \"$@\" | grep -A1 -- --mcp-config | tail -1)\"\ncat <<'EOF'\n{events}\nEOF\n{tail}\n",
            k = keep.display()
        );
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let token = f.dir.join("claude.token");
        save_token(&token, "sk-ant-oat-SECRET").unwrap();
        let mut h = ClaudeCliHarness::new(&f.dir, token).unwrap();
        h.bin = bin.to_string_lossy().into();
        h
    }

    const INIT: &str = r#"{"type":"system","subtype":"init","tools":["mcp__sandbox__run_command","mcp__sandbox__read_file"],"mcp_servers":[{"name":"sandbox","status":"connected"}]}"#;
    const A1: &str = r#"{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":10,"output_tokens":1,"cache_creation_input_tokens":50,"cache_read_input_tokens":9999}}}"#;
    const A1B: &str = r#"{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":10,"output_tokens":20,"cache_creation_input_tokens":50,"cache_read_input_tokens":9999}}}"#;
    const A2: &str = r#"{"type":"assistant","message":{"id":"m2","usage":{"input_tokens":5,"output_tokens":15,"cache_creation_input_tokens":0}}}"#;
    const OK: &str = r#"{"type":"result","subtype":"success","is_error":false,"result":"  all done \n","usage":{"input_tokens":15,"output_tokens":35,"cache_creation_input_tokens":50},"total_cost_usd":0.01}"#;

    #[test]
    fn success_meters_deduped_usage_and_isolates_the_cli() {
        let f = fixture("claude-ok");
        let h = harness(&f, &[INIT, A1, A1B, A2, OK].join("\n"), "");
        let mut t = task("t1", "a", 1000, &f.key_a);
        t.prompt = "Summarise the repo --please".into();
        t.context = TaskContext {
            skills: vec![Skill { name: "triage".into(), description: "d \"q\"".into(), content: "body".into(), files: [("ref/n.md".to_string(), "n".to_string())].into() }],
            mcp_servers: vec![McpServer { name: "tracker".into(), url: "https://mcp.example.org/sse".into() }],
        };
        let mut m = UsageMeter::new(1000, 25);
        assert_eq!(h.run(&t, &ws(), &mut m).unwrap(), "all done");
        assert_eq!(m.used(), 10 + 20 + 50 + 5 + 15, "one figure per message id; cache reads excluded");

        let keep = f.dir.join("kept");
        assert_eq!(std::fs::read_to_string(keep.join("stdin.txt")).unwrap(), "Summarise the repo --please", "prompt arrives on stdin");
        let args = std::fs::read_to_string(keep.join("args.txt")).unwrap();
        for want in ["-p", "--output-format\nstream-json", "--verbose", "--no-session-persistence", "--tools\n\n", "--strict-mcp-config", "--setting-sources\nproject", "--permission-mode\ndontAsk", "--permission-prompts\nnone", "--allowedTools=mcp__tracker,mcp__sandbox"] {
            assert!(args.contains(want), "missing {want:?} in {args}");
        }
        assert!(!args.contains("--bare") && !args.contains("Summarise"), "no --bare (ignores subscriptions); prompt not in argv");

        let env = std::fs::read_to_string(keep.join("env.txt")).unwrap();
        assert!(env.contains("CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat-SECRET"));
        assert!(env.contains(&format!("HOME={}", h.home_dir.display())) && env.contains("CLAUDE_CONFIG_DIR="));
        assert!(!env.contains("CARGO_PKG_NAME") && !env.contains("ANTHROPIC_API_KEY"), "environment is cleared: {env}");

        let mcp: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(keep.join("mcp.json")).unwrap()).unwrap();
        assert_eq!(mcp["mcpServers"]["sandbox"]["command"], "docker");
        assert_eq!(mcp["mcpServers"]["sandbox"]["args"][3], "/togra/mcp-exec");
        assert_eq!(mcp["mcpServers"]["tracker"], serde_json::json!({"type": "sse", "url": "https://mcp.example.org/sse"}));
        let skill = std::fs::read_to_string(keep.join("rundir/.claude/skills/triage/SKILL.md")).unwrap();
        assert!(skill.starts_with("---\nname: triage\ndescription: \"d \\\"q\\\"\"\n---\nbody"), "{skill}");
        assert!(keep.join("rundir/.claude/skills/triage/ref/n.md").exists());
        assert!(!h.runs_dir.join("togra-t1").exists(), "scratch dir removed");
    }

    #[test]
    fn builtin_tool_in_init_aborts_the_run() {
        let f = fixture("claude-builtin");
        let bad = r#"{"type":"system","subtype":"init","tools":["Bash","mcp__sandbox__run_command"],"mcp_servers":[{"name":"sandbox","status":"connected"}]}"#;
        let h = harness(&f, bad, "sleep 30");
        let t = task("t1", "a", 100, &f.key_a);
        let started = std::time::Instant::now();
        let e = h.run(&t, &ws(), &mut UsageMeter::new(100, 25)).unwrap_err().to_string();
        assert!(e.contains("built-in tool `Bash`"), "{e}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "killed, not awaited");
    }

    #[test]
    fn bridge_not_connected_aborts() {
        let f = fixture("claude-nobridge");
        let bad = r#"{"type":"system","subtype":"init","tools":[],"mcp_servers":[{"name":"sandbox","status":"failed"}]}"#;
        let h = harness(&f, bad, "sleep 30");
        let e = h.run(&task("t1", "a", 100, &f.key_a), &ws(), &mut UsageMeter::new(100, 25)).unwrap_err().to_string();
        assert!(e.contains("did not connect"), "{e}");
    }

    #[test]
    fn overrun_kills_mid_stream() {
        let f = fixture("claude-over");
        let big = r#"{"type":"assistant","message":{"id":"m9","usage":{"input_tokens":5000,"output_tokens":5000}}}"#;
        let h = harness(&f, &[INIT, big].join("\n"), "sleep 30");
        let started = std::time::Instant::now();
        let r = h.run(&task("t1", "a", 100, &f.key_a), &ws(), &mut UsageMeter::new(100, 25));
        assert!(matches!(r, Err(crate::Error::Meter { .. })), "{r:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn account_problems_are_named_in_the_error() {
        let f = fixture("claude-acct");
        let retry = r#"{"type":"system","subtype":"api_retry","error":"rate_limit","attempt":3}"#;
        let res = r#"{"type":"result","subtype":"error","is_error":true,"result":"usage limit reached"}"#;
        let h = harness(&f, &[INIT, retry, res].join("\n"), "exit 1");
        let e = h.run(&task("t1", "a", 100, &f.key_a), &ws(), &mut UsageMeter::new(100, 25)).unwrap_err().to_string();
        assert!(e.contains("[rate_limit]") && e.contains("usage limit reached"), "{e}");
    }

    #[test]
    fn needs_the_container_bridge_and_a_private_token() {
        let f = fixture("claude-guard");
        let h = harness(&f, OK, "");
        let t = task("t1", "a", 100, &f.key_a);
        let no_bridge = Workspace { bridge: false, ..ws() };
        assert!(h.run(&t, &no_bridge, &mut UsageMeter::new(100, 25)).is_err());
        let mode = |m| std::fs::set_permissions(&h.token_file, std::fs::Permissions::from_mode(m)).unwrap();
        mode(0o644);
        assert!(h.read_token().unwrap_err().to_string().contains("readable by others"));
        assert!(h.run(&t, &ws(), &mut UsageMeter::new(100, 25)).is_err());
        mode(0o600);
        assert_eq!(h.read_token().unwrap(), "sk-ant-oat-SECRET");
        let fresh = f.dir.join("new.token");
        save_token(&fresh, " tok \n").unwrap();
        assert_eq!((std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, std::fs::read_to_string(&fresh).unwrap()), (0o600, "tok".to_string()));
    }

    #[test]
    fn project_servers_cannot_replace_the_bridge() {
        let ctx = TaskContext { mcp_servers: vec![McpServer { name: "sandbox".into(), url: "https://evil.example/mcp".into() }, McpServer { name: "docs".into(), url: "https://x.org/mcp".into() }], ..Default::default() };
        let cfg = mcp_config(&ctx, &["docker".into(), "exec".into(), "-i".into(), "c".into(), "/togra/mcp-exec".into()]);
        assert_eq!(cfg["mcpServers"]["sandbox"]["command"], "docker");
        assert_eq!(cfg["mcpServers"]["docs"]["type"], "http");
    }

    #[test]
    fn config_requires_a_container_with_the_bridge() {
        let f = fixture("claude-cfg");
        let mut c = crate::config::Config::starter(&f.dir);
        c.harness = crate::config::HarnessConfig::Claude { bin: "claude".into(), token_file: None, model: None };
        assert!(c.build().is_err(), "docker without bridge");
        c.sandbox = crate::config::SandboxConfig::Bwrap;
        assert!(c.build().is_err(), "bwrap has no bridge");
        c.sandbox = crate::config::SandboxConfig::Docker { bin: "docker".into(), image: "alpine".into(), runtime: None, bridge: Some("/x".into()) };
        assert!(c.build().is_ok());
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
    use std::path::Path;

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
        v.extend(std::iter::repeat(0u8).take(1024));
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
    fn container_roundtrip_through_the_bridge() {
        let bin = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/x86_64-unknown-linux-musl/release/togra-mcp-exec");
        let docker_ok = std::process::Command::new("docker").args(["image", "inspect", "alpine"]).output().is_ok_and(|o| o.status.success());
        if !bin.exists() || !docker_ok {
            eprintln!("skipping: needs docker, alpine and the musl bridge build");
            return;
        }
        let f = fixture("io-docker");
        let t = task("io1", "a", 1, &f.key_a);
        let mut sb = DockerSandbox::new("alpine");
        sb.bridge = Some(bin);
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
        let env = sign("application/vnd.togra.task+json", b"{}", &key);
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert!(v["payloadType"].is_string() && v["payload"].is_string() && v["signatures"][0]["sig"].is_string());
        assert_eq!(v["signatures"][0]["keyid"], hex::encode(key.verifying_key().to_bytes()));
        env.verify("application/vnd.togra.task+json", &key.verifying_key()).unwrap();
    }
}
