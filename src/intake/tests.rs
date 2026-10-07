//! Intake tests: the task lifecycle, the approval policy and the state branch, then the whole sync
//! pass against the fake GitHub (in `crate::tests::github_queue`), the Projects board and email.

use super::policy::*;
use super::task::*;
use super::*;
use chrono::{DateTime, Duration, TimeZone, Utc};

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 7, 9, 0, 0).unwrap()
}

fn turn(src: &str, role: Role, author: &str, text: &str, approved: bool) -> Turn {
    Turn { source: ItemRef::new(src), role, author: author.into(), text: text.into(), approved, at: t0() }
}

fn rules() -> Rules {
    Rules { attempt_cap: 2 }
}

fn new_task(approved: bool) -> Task {
    let mut t = Task::new("acme", turn("github:issue:1", Role::Request, "github:alice", "fix the typo", approved), "docs", "Fix the typo", 1000, None, t0());
    t.start(rules());
    t
}

fn result(text: &str) -> AttemptResult {
    AttemptResult { output: text.into(), tokens_used: 100, runner: "r".into(), outcome: "pull request".into() }
}

fn post(t: &mut Task, n: u32) -> Vec<Effect> {
    t.apply(Event::Posted { manifest_id: t.manifest_id(n), issue: Some(10 + u64::from(n)) }, rules(), t0()).unwrap()
}

#[test]
fn an_approved_request_queues_its_first_attempt() {
    let mut t = new_task(true);
    assert_eq!(t.state, State::Queued);
    assert_eq!(t.start(rules()), [Effect::PostAttempt { attempt: 1 }], "idempotent: a pass that failed before posting posts again");
    assert_eq!(t.id, task_id_for(&ItemRef::new("github:issue:1")), "the id comes from the request, so a repeat is the same task");
    post(&mut t, 1);
    assert_eq!(t.state, State::Running { attempt: 1 });
    assert_eq!(t.attempts[0].manifest_id, format!("{}-a1", t.id));
    let fx = t.apply(Event::Result { attempt: 1, result: result("done it"), pr: Some(500) }, rules(), t0()).unwrap();
    assert_eq!(fx, [Effect::Publish]);
    assert_eq!(t.state, State::AwaitingFeedback { attempt: 1 });
    assert_eq!((t.pr, t.tokens_used), (Some(500), 100));
    assert!(t.links.contains(&ItemRef::new("github:pr:500")));
}

#[test]
fn an_unapproved_request_waits_for_a_maintainer() {
    let mut t = new_task(false);
    assert_eq!(t.state, State::Draft);
    assert!(t.note.as_deref().unwrap_or("").contains("/approve"), "{:?}", t.note);
    let fx = t.apply(Event::Approve, rules(), t0()).unwrap();
    assert_eq!(fx, [Effect::PostAttempt { attempt: 1 }, Effect::Publish]);
    assert_eq!((t.state.clone(), t.note.clone()), (State::Queued, None));
}

#[test]
fn refinements_while_running_are_batched_into_the_next_attempt() {
    let mut t = new_task(true);
    post(&mut t, 1);
    let r1 = turn("github:comment:1", Role::Refinement, "github:alice", "also the second typo", true);
    let r2 = turn("github:comment:2", Role::Refinement, "github:alice", "and the third", true);
    assert_eq!(t.apply(Event::Refine(r1.clone()), rules(), t0()).unwrap(), [Effect::Publish]);
    t.apply(Event::Refine(r2), rules(), t0()).unwrap();
    assert_eq!(t.apply(Event::Refine(r1), rules(), t0()).unwrap(), [], "a repeated delivery changes nothing");
    assert_eq!(t.state, State::Running { attempt: 1 }, "nothing starts while an attempt runs");
    let fx = t.apply(Event::Result { attempt: 1, result: result("first"), pr: Some(500) }, rules(), t0()).unwrap();
    assert_eq!(fx, [Effect::PostAttempt { attempt: 2 }, Effect::Publish], "both refinements go into attempt 2 at once");
    post(&mut t, 2);
    assert_eq!(t.attempts[1].upto, t.conversation.len());
    assert_eq!(t.pending().count(), 0);
}

#[test]
fn the_attempt_cap_needs_a_maintainer_and_results_for_other_attempts_are_ignored() {
    let mut t = new_task(true);
    for n in 1..=2 {
        post(&mut t, n);
        assert_eq!(t.apply(Event::Result { attempt: n + 5, result: result("stray"), pr: None }, rules(), t0()).unwrap(), [], "not the running attempt");
        t.apply(Event::Result { attempt: n, result: result("ok"), pr: Some(500) }, rules(), t0()).unwrap();
        t.apply(Event::Refine(turn(&format!("c{n}"), Role::Refinement, "github:alice", "more", true)), rules(), t0()).unwrap();
    }
    assert_eq!(t.state, State::Draft, "two attempts is the cap here");
    assert!(t.note.as_deref().unwrap().contains("cap"), "{:?}", t.note);
    assert_eq!(t.apply(Event::Approve, rules(), t0()).unwrap(), [Effect::PostAttempt { attempt: 3 }, Effect::Publish]);
    post(&mut t, 3);
    assert!(!t.cap_override, "the override is spent on one attempt");
    assert!(t.apply(Event::Posted { manifest_id: "x".into(), issue: None }, rules(), t0()).is_err(), "posting is only valid while queued");
}

#[test]
fn done_cancel_reopen_stale_and_a_comment_after_done() {
    let mut t = new_task(true);
    post(&mut t, 1);
    assert_eq!(t.apply(Event::Stale, rules(), t0()).unwrap(), [], "a running task is never stale");
    t.apply(Event::Result { attempt: 1, result: result("ok"), pr: Some(500) }, rules(), t0()).unwrap();
    assert_eq!(t.apply(Event::Done, rules(), t0()).unwrap(), [Effect::Close, Effect::Publish]);
    assert_eq!(t.apply(Event::Done, rules(), t0()).unwrap(), [], "twice is once");
    assert_eq!(t.apply(Event::Approve, rules(), t0()).unwrap(), []);
    t.apply(Event::Reopen, rules(), t0()).unwrap();
    assert_eq!(t.state, State::AwaitingFeedback { attempt: 1 });
    t.apply(Event::Cancel, rules(), t0()).unwrap();
    assert_eq!(t.state, State::Cancelled);
    let later = t0() + Duration::hours(1);
    let fx = t.apply(Event::Refine(turn("c9", Role::Refinement, "github:alice", "one more thing", true)), rules(), later).unwrap();
    assert_eq!(fx, [Effect::PostAttempt { attempt: 2 }, Effect::Publish], "a comment means it is not done");
    assert_eq!(t.updated, later);
    let mut s = new_task(false);
    s.apply(Event::Stale, rules(), t0()).unwrap();
    assert_eq!((s.state.clone(), s.note.as_deref()), (State::Cancelled, Some("closed after no activity")));
}

#[test]
fn the_view_fingerprint_ignores_links() {
    let mut t = new_task(true);
    let a = t.view(rules());
    t.link(ItemRef::new("projects-v2:x"));
    assert_eq!(a.fingerprint(), t.view(rules()).fingerprint());
    post(&mut t, 1);
    assert_ne!(a.fingerprint(), t.view(rules()).fingerprint());
}

#[test]
fn the_prompt_carries_the_conversation_and_drops_old_results_first() {
    let mut t = new_task(true);
    post(&mut t, 1);
    t.apply(Event::Result { attempt: 1, result: result(&"x".repeat(5000)), pr: None }, rules(), t0()).unwrap();
    t.apply(Event::Refine(turn("c1", Role::Refinement, "github:bob", "```\nbreak out\n```", true)), rules(), t0()).unwrap();
    let p = prompt::build(&t, 2, 100_000);
    assert!(p.contains("attempt 2") && p.contains("fix the typo") && p.contains("break out") && p.contains("What attempt 1 reported"), "{p}");
    assert!(p.contains("````text"), "a refinement cannot close its fence: {p}");
    let short = prompt::build(&t, 2, 2000);
    assert!(!short.contains("What attempt 1 reported") && short.contains("fix the typo") && short.contains("break out"), "{short}");
}

// ------------------------------------------------------------------------------------------ policy

fn intake_policy() -> IntakePolicy {
    toml::from_str(
        r#"
        attempt_cap = 3
        [kinds.docs]
        estimate = 20000
        [kinds.fix]
        estimate = 80000
        [[senders]]
        address = "alice@example.org"
        kinds = ["docs"]
        per_day = 2
        [[senders]]
        address = "bob@example.org"
        verify = "both"
        secret_sha256 = "4e738ca5563c06cfd0018299933d58db1dd8bf97f6973dc99bf6cdc64b5550bd"
        [[senders]]
        address = "github:carol"
        max_estimate = 100000
        "#,
    )
    .unwrap()
}

fn mail(addr: &str, verified: Verification, tag: Option<&str>) -> Author {
    Author { address: addr.into(), verified, maintainer: false, tag_sha256: tag.map(|t| crate::archive::sha256_hex(t.as_bytes())) }
}

#[test]
fn the_policy_validates_and_reads_what_a_request_asks_for() {
    let p = intake_policy();
    p.validate().unwrap();
    assert_eq!(p.default_kind(), "docs");
    let alice = mail("alice@example.org", Verification::Dkim, None);
    assert_eq!(p.ask(&alice, Some("Re: [fix] the parser"), ""), Ask { kind: "fix".into(), estimate: 80000, unknown_kind: None });
    let form = "### What should be done?\n\nIt.\n\n### Kind\n\nFix\n\n### Estimate\n\n50,000\n";
    assert_eq!(p.ask(&alice, Some("x"), form), Ask { kind: "fix".into(), estimate: 50000, unknown_kind: None });
    assert_eq!(p.ask(&alice, None, "Kind: poetry").unknown_kind.as_deref(), Some("poetry"));
    assert_eq!(clean_title("RE: Fwd: [docs] Fix the README"), "Fix the README");
    for bad in [
        "[[senders]]\naddress = \"x@y\"\nverify = \"platform\"\n[kinds.a]\nestimate = 1",
        "[[senders]]\naddress = \"x@y\"\nverify = \"secret-address\"\n[kinds.a]\nestimate = 1",
        "[[senders]]\naddress = \"X@y\"\n[kinds.a]\nestimate = 1",
        "default_kind = \"b\"\n[kinds.a]\nestimate = 1",
        "",
    ] {
        assert!(toml::from_str::<IntakePolicy>(bad).unwrap().validate().is_err(), "{bad}");
    }
}

#[test]
fn senders_are_accepted_within_their_limits_and_verification() {
    let p = intake_policy();
    let docs = Ask { kind: "docs".into(), estimate: 20000, unknown_kind: None };
    let fix = Ask { kind: "fix".into(), estimate: 80000, unknown_kind: None };
    let alice = mail("alice@example.org", Verification::Dkim, None);
    assert_eq!(p.decide_message(&alice, &docs, 0), Decision::Accept);
    assert!(matches!(p.decide_message(&alice, &docs, 2), Decision::Hold(w) if w.contains("per day")));
    assert!(matches!(p.decide_message(&alice, &fix, 0), Decision::Hold(w) if w.contains("may not ask")));
    assert!(matches!(p.decide_message(&alice, &Ask { estimate: 20001, ..docs.clone() }, 0), Decision::Hold(w) if w.contains("estimate")));
    assert!(matches!(p.decide_message(&mail("alice@example.org", Verification::None, None), &docs, 0), Decision::Ignore(_)), "DKIM failed: dropped");
    assert!(matches!(p.decide_message(&mail("eve@example.org", Verification::Dkim, None), &docs, 0), Decision::Ignore(_)), "unknown mail is dropped");
    // bob needs DKIM and the secret address
    let secret = "s3cr3t";
    assert_eq!(p.verification(&mail("bob@example.org", Verification::Dkim, Some(secret))), Verification::Both);
    assert!(matches!(p.decide_message(&mail("bob@example.org", Verification::Dkim, None), &docs, 0), Decision::Ignore(_)));
    assert!(matches!(p.decide_message(&mail("bob@example.org", Verification::Dkim, Some("wrong")), &docs, 0), Decision::Ignore(_)));
    assert_eq!(p.decide_message(&mail("bob@example.org", Verification::Dkim, Some(secret)), &docs, 0), Decision::Accept);
    // GitHub: pre-approved, maintainer, and anyone else (held: they can be seen and approved)
    assert_eq!(p.decide_message(&Author::platform("carol", false), &fix, 0), Decision::Accept);
    assert_eq!(p.decide_message(&Author::platform("dave", true), &fix, 0), Decision::Accept);
    assert!(matches!(p.decide_message(&Author::platform("mallory", false), &docs, 0), Decision::Hold(_)));
    let forged = Author { maintainer: true, ..mail("alice@example.org", Verification::Dkim, None) };
    assert!(!p.is_maintainer(&forged), "only the platform vouches for maintainers");
}

#[test]
fn signals_need_a_maintainer_or_whoever_asked() {
    let p = intake_policy();
    let t = new_task(true); // asked by github:alice
    assert_eq!(p.decide_signal(&Author::platform("dave", true), SignalKind::Approve, &t), Decision::Accept);
    assert!(matches!(p.decide_signal(&Author::platform("alice", false), SignalKind::Approve, &t), Decision::Ignore(_)));
    assert_eq!(p.decide_signal(&Author::platform("alice", false), SignalKind::Done, &t), Decision::Accept);
    assert!(matches!(p.decide_signal(&Author::platform("mallory", false), SignalKind::Cancel, &t), Decision::Ignore(_)));
    assert_eq!(SignalKind::from_command("  /done thanks\nmore"), Some(SignalKind::Done));
    assert_eq!(SignalKind::from_command("please /done"), None);
}

// ------------------------------------------------------------------------------------- state branch

pub(crate) fn git(dir: &std::path::Path, args: &[&str]) -> String {
    let o = std::process::Command::new("git").current_dir(dir).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A bare origin and a clone of it with `main` holding the given files.
pub(crate) fn repo(name: &str, files: &[(&str, &str)]) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("toto-intake-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
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

#[test]
fn the_state_branch_round_trips_and_detects_a_concurrent_pass() {
    let (remote, work) = repo("store", &[("README", "hi")]);
    let mut a = store::Store::open(&work, "toto-state").unwrap();
    assert!(a.list("tasks/").is_empty());
    assert_eq!(a.commit_and_push("nothing").unwrap(), None, "no change, no commit");
    a.put("tasks/t-1.json", &serde_json::json!({"x": 1})).unwrap();
    a.append("log/2026-10-07.jsonl", "{\"a\":1}");
    a.append("log/2026-10-07.jsonl", "{\"a\":2}");
    a.commit_and_push("first").unwrap().unwrap();
    assert_eq!(git(&work, &["status", "--porcelain"]), "", "the checkout is not touched");
    assert_eq!(git(&remote, &["rev-parse", "main"]), git(&work, &["rev-parse", "HEAD"]), "main is not written");

    // two passes read the same state; the second to push loses
    let mut b = store::Store::open(&work, "toto-state").unwrap();
    let mut c = store::Store::open(&work, "toto-state").unwrap();
    assert_eq!(b.get::<serde_json::Value>("tasks/t-1.json").unwrap().unwrap()["x"], 1);
    assert_eq!(b.raw("log/2026-10-07.jsonl").unwrap(), b"{\"a\":1}\n{\"a\":2}\n");
    b.put("tasks/t-1.json", &serde_json::json!({"x": 2})).unwrap();
    b.put("tasks/t-1.json", &serde_json::json!({"x": 2})).unwrap();
    b.commit_and_push("b").unwrap().unwrap();
    c.put("cursors/github.json", &serde_json::json!({})).unwrap();
    assert!(matches!(c.commit_and_push("c"), Err(crate::Error::Concurrent(_))));
    let d = store::Store::open(&work, "toto-state").unwrap();
    assert_eq!(d.get::<serde_json::Value>("tasks/t-1.json").unwrap().unwrap()["x"], 2);
    assert!(d.raw("cursors/github.json").is_none());
    assert_eq!(git(&remote, &["rev-list", "--count", "toto-state"]), "2", "{}", git(&remote, &["log", "--oneline", "toto-state"]));
}

#[test]
fn a_bundle_is_the_tree_at_a_revision() {
    let (_, work) = repo("bundle", &[("README", "hi"), ("src/a.rs", "fn a() {}")]);
    std::os::unix::fs::symlink("README", work.join("link")).unwrap();
    git(&work, &["add", "link"]);
    git(&work, &["commit", "-q", "-m", "link"]);
    let records = git::bundle(&work, "HEAD", crate::archive::Limits::new(1 << 20)).unwrap();
    let paths: Vec<String> = records.iter().map(|r| match r {
        crate::archive::Record::File { path, .. } | crate::archive::Record::Deleted { path } => path.clone(),
    }).collect();
    assert_eq!(paths, ["README", "src/a.rs"], "symlinks are not carried");
    assert!(git::bundle(&work, "HEAD", crate::archive::Limits::new(3)).is_err());
}

// ------------------------------------------------------------------------- the sync pass, end to end

mod e2e {
    use super::super::sync::{sync_repo, IntakeConfig, Report, Secrets};
    use super::super::task::State;
    use super::{git, repo};
    use crate::archive::Record;
    use crate::manifest::{TaskManifest, TrustedProjects};
    use crate::queue::QueueClient;
    use crate::tests::github_queue::{Fake, BOT, TOKEN};
    use ed25519_dalek::SigningKey;
    use std::path::PathBuf;

    pub(super) struct World {
        pub(super) fake: Fake,
        pub(super) key: SigningKey,
        pub(super) remote: PathBuf,
        pub(super) work: PathBuf,
        pub(super) cfg: IntakeConfig,
    }

    pub(super) const BASE_CONFIG: &str = r#"
        project_id = "acme"
        repo = "org/proj"
        [kinds.docs]
        estimate = 1000
        tool_requirements = ["echo"]
    "#;

    pub(super) fn world(name: &str, extra: &str) -> World {
        let (remote, work) = repo(name, &[("README", "hello\n"), ("docs/guide.md", "# Guide\n")]);
        let fake = Fake::start();
        fake.state.lock().unwrap().permissions.insert("maint".into(), "write".into());
        let cfg = IntakeConfig::parse(&format!("{BASE_CONFIG}\n{extra}")).unwrap();
        World { fake, key: crate::manifest::generate_key(), remote, work, cfg }
    }

    impl World {
        pub(super) fn secrets(&self) -> Secrets {
            Secrets { api: self.fake.api(), github_token: TOKEN.into(), projects_token: Some("board-token".into()), imap_password: None }
        }
        pub(super) fn pass(&self) -> Report {
            let r = sync_repo(&self.cfg, &self.work, &self.key, &self.secrets(), chrono::Utc::now()).unwrap();
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            r
        }
        pub(super) fn tasks(&self) -> Vec<super::super::task::Task> {
            let s = super::super::store::Store::open(&self.work, "toto-state").unwrap();
            s.list("tasks/").iter().map(|p| s.get(p).unwrap().unwrap()).collect()
        }
        pub(super) fn task(&self) -> super::super::task::Task {
            let mut t = self.tasks();
            assert_eq!(t.len(), 1, "{t:?}");
            t.remove(0)
        }
        pub(super) fn trusted(&self) -> TrustedProjects {
            self.cfg.trusted(&self.key)
        }
        /// What a contributor's runner does with the one available task: verify it, read its
        /// bundle, and submit a result changing `files`.
        pub(super) fn run_attempt(&self, files: &[(&str, &str)], output: &str) -> (TaskManifest, Vec<Record>) {
            let q = self.fake.queue(Some(TOKEN));
            let envs = q.available().unwrap();
            assert_eq!(envs.len(), 1, "one attempt is available");
            let m = self.trusted().verify(&envs[0]).unwrap();
            let bundle = crate::archive::from_bytes(&q.bundle(&m.inputs).unwrap().unwrap(), crate::archive::Limits::new(1 << 20)).unwrap();
            let records: Vec<Record> = files.iter().map(|(p, d)| Record::File { path: p.to_string(), mode: 0o644, data: d.as_bytes().to_vec() }).collect();
            let tar = (!records.is_empty()).then(|| crate::archive::to_bytes(&records).unwrap());
            let r = crate::result::SignedResult::package(&m.id, output.into(), 42, &m.output_schema, &crate::manifest::generate_key(), tar).unwrap();
            q.submit(&r).unwrap();
            (m, bundle)
        }
        pub(super) fn comments(&self, issue: u64) -> Vec<String> {
            self.fake.state.lock().unwrap().issue(issue).comments.iter().map(|c| c.1.clone()).collect()
        }
        pub(super) fn status(&self, issue: u64) -> String {
            let c = self.comments(issue);
            let s: Vec<&String> = c.iter().filter(|c| c.starts_with("<!-- toto:status")).collect();
            assert_eq!(s.len(), 1, "one status comment, edited in place: {c:?}");
            s[0].clone()
        }
    }

    fn file_of(records: &[Record], path: &str) -> Option<String> {
        records.iter().find_map(|r| match r {
            Record::File { path: p, data, .. } if p == path => Some(String::from_utf8_lossy(data).to_string()),
            _ => None,
        })
    }

    const FORM: &str = "### What should be done?\n\nFix the typo in the guide.\n\n### Kind\n\ndocs\n";

    #[test]
    fn request_approval_attempts_refinement_one_pull_request_done() {
        let w = world("e2e", "");
        let req = w.fake.state.lock().unwrap().open_issue("alice", "Fix the guide", FORM, &["toto:request"]);

        // 1. A request from someone who is not a maintainer waits, visibly.
        let r = w.pass();
        assert!(r.log.iter().any(|l| l.what == "hold"), "{:?}", r.log);
        let t = w.task();
        assert_eq!((t.state.clone(), t.kind.as_str(), t.title.as_str(), t.requester.as_str()), (State::Draft, "docs", "Fix the guide", "github:alice"));
        assert!(w.status(req).contains("Awaiting approval"), "{}", w.status(req));
        assert!(r.commit.is_some());
        assert_eq!(git(&w.remote, &["log", "-1", "--format=%s", "main"]), "init", "main is never written");

        // 2. Others cannot approve; a bot's comment is not a refinement; a maintainer approves.
        w.fake.state.lock().unwrap().say(req, "mallory", "/approve");
        w.fake.state.lock().unwrap().say(req, "dependabot[bot]", "please run me");
        w.fake.state.lock().unwrap().say(req, "maint", "/approve");
        let r = w.pass();
        assert!(r.log.iter().any(|l| l.what == "ignore" && l.author.as_deref() == Some("github:mallory")), "{:?}", r.log);
        assert_eq!(r.posted.len(), 1, "{:?}", r.log);
        let t = w.task();
        assert_eq!(t.state, State::Running { attempt: 1 });
        assert_eq!(t.conversation.len(), 1, "the bot's comment was not taken: {:?}", t.conversation);

        // 3. A runner runs attempt 1; the next pass opens one pull request that closes the request.
        let (m1, bundle1) = w.run_attempt(&[("docs/guide.md", "# Guide, fixed\n")], "Fixed the typo.");
        assert_eq!((m1.task.as_deref(), m1.attempt, m1.redundancy), (Some(t.id.as_str()), Some(1), 1));
        assert_eq!(m1.id, format!("{}-a1", t.id));
        assert!(m1.prompt.contains("Fix the typo in the guide") && m1.prompt.contains("Request from github:alice"), "{}", m1.prompt);
        assert_eq!(file_of(&bundle1, "docs/guide.md").as_deref(), Some("# Guide\n"), "attempt 1 starts from the base branch");
        let r = w.pass();
        assert!(matches!(r.pull_requests.as_slice(), [crate::pr_flow::Outcome::PullRequest { number: 500, .. }]), "{:?}", r.pull_requests);
        let t = w.task();
        assert_eq!((t.state.clone(), t.pr, t.tokens_used), (State::AwaitingFeedback { attempt: 1 }, Some(500), 42));
        let branch = format!("toto/{}", t.id);
        {
            let st = w.fake.state.lock().unwrap();
            assert_eq!(st.pulls.len(), 1);
            assert_eq!(st.pulls[0].1, branch);
            assert!(st.pulls[0].4.starts_with(&format!("Closes #{req}")), "{}", st.pulls[0].4);
        }
        let status = w.status(req);
        assert!(status.contains("Awaiting feedback") && status.contains("#500") && status.contains("Fixed the typo"), "{status}");

        // 4. A maintainer's comment on the pull request refines the task: attempt 2 starts from the
        //    task's branch, carries the conversation, and lands on the same pull request.
        w.fake.state.lock().unwrap().say(500, "maint", "Also add a section on installing.");
        let r = w.pass();
        assert_eq!(r.posted.len(), 1, "{:?}", r.log);
        let (m2, bundle2) = w.run_attempt(&[("docs/install.md", "# Install\n")], "Added the section.");
        assert_eq!(m2.attempt, Some(2));
        assert!(m2.prompt.contains("attempt 2") && m2.prompt.contains("installing") && m2.prompt.contains("Fixed the typo"), "{}", m2.prompt);
        assert_eq!(file_of(&bundle2, "docs/guide.md").as_deref(), Some("# Guide, fixed\n"), "attempt 2 continues from attempt 1's work");
        let r = w.pass();
        assert!(matches!(r.pull_requests.as_slice(), [crate::pr_flow::Outcome::PullRequest { number: 500, .. }]), "{:?}", r.pull_requests);
        assert_eq!(w.fake.state.lock().unwrap().pulls.len(), 1, "still one pull request");
        let log = git(&w.remote, &["log", "--format=%s", &branch]);
        assert_eq!(log.lines().count(), 3, "init and one commit per attempt: {log}");
        assert!(git(&w.remote, &["log", "--format=%B", &branch]).contains(&format!("Toto-Attempt: {}", m2.id)));
        assert!(w.comments(500).iter().any(|c| c.contains("Attempt 2")), "{:?}", w.comments(500));
        assert_eq!(w.task().state, State::AwaitingFeedback { attempt: 2 });

        // 5. `/done` ends it: the request issue is closed, and nothing changes afterwards.
        w.fake.state.lock().unwrap().say(req, "alice", "/done");
        w.pass();
        assert_eq!(w.task().state, State::Done);
        assert!(w.fake.state.lock().unwrap().issue(req).closed);
        let echo = w.pass(); // sees toto's own closing: the cursor moves, nothing else
        assert!(echo.log.is_empty(), "{:?}", echo.log);
        let quiet = w.pass();
        assert_eq!((quiet.commit.clone(), quiet.posted.len(), quiet.published), (None, 0, 0), "{:?}", quiet.log);
    }

    #[test]
    fn merging_ends_a_task_and_cancelling_closes_its_pull_request() {
        for (name, merge) in [("e2e-merge", true), ("e2e-cancel", false)] {
            let w = world(name, "[[senders]]\naddress = \"github:alice\"\n");
            let req = w.fake.state.lock().unwrap().open_issue("alice", "Fix it", FORM, &["toto:request"]);
            w.pass();
            w.run_attempt(&[("docs/guide.md", "fixed\n")], "ok");
            w.pass();
            assert_eq!(w.task().pr, Some(500));
            if merge {
                let mut st = w.fake.state.lock().unwrap();
                let pr = st.issue_mut(500);
                (pr.merged, pr.closed, pr.updated) = (true, true, chrono::Utc::now().timestamp() + 5);
            } else {
                w.fake.state.lock().unwrap().say(req, "alice", "/cancel");
            }
            w.pass();
            let t = w.task();
            let st = w.fake.state.lock().unwrap();
            if merge {
                assert_eq!(t.state, State::Done);
                assert!(st.issue(req).closed, "the request issue is closed with the task");
            } else {
                assert_eq!(t.state, State::Cancelled);
                assert!(st.issue(500).closed && !st.issue(500).merged, "a cancelled task's pull request is closed");
                assert!(st.issue(req).closed);
            }
        }
    }

    #[test]
    fn a_pass_that_lost_its_state_does_not_post_twice() {
        let w = world("e2e-idem", "[[senders]]\naddress = \"github:alice\"\n");
        w.fake.state.lock().unwrap().open_issue("alice", "Fix it", FORM, &["toto:request"]);
        let before = w.pass(); // pre-approved: posted at once
        assert_eq!(before.posted.len(), 1);
        // As if that pass had failed to push its state: put the state branch back to nothing.
        git(&w.remote, &["update-ref", "-d", "refs/heads/toto-state"]);
        let again = w.pass();
        assert_eq!(again.posted.len(), 1, "the attempt is found, not posted again: {:?}", again.log);
        let tasks = w.fake.queue(Some(TOKEN)).task_index(&w.trusted()).unwrap();
        assert_eq!(tasks.len(), 1, "{tasks:?}");
        assert_eq!(w.task().state, State::Running { attempt: 1 });
        // A forged issue claiming the next attempt's id does not count as posted.
        let t = w.task();
        let mut forged = super::super::super::tests::github_queue_task(&format!("{}-a2", t.id));
        forged.project_id = "acme".into();
        let env = forged.sign(&crate::manifest::generate_key()).unwrap();
        w.fake.queue(Some(TOKEN)).post_task(&env).unwrap();
        assert!(!w.fake.queue(Some(TOKEN)).task_index(&w.trusted()).unwrap().contains_key(&format!("{}-a2", t.id)));
        let _ = BOT;
    }
}

#[test]
fn old_manifests_still_verify_and_new_fields_are_signed() {
    let key = crate::manifest::generate_key();
    let mut trusted = crate::manifest::TrustedProjects::default();
    trusted.insert("a", key.verifying_key());
    // A manifest as an older project would sign it: no task or attempt fields at all.
    let old = crate::tests::github_queue_task("old-1");
    let json = serde_json::to_string(&old).unwrap();
    assert!(!json.contains("\"task\"") && !json.contains("\"attempt\""), "{json}");
    let env = crate::dsse::sign(crate::manifest::TASK_PAYLOAD_TYPE, json.as_bytes(), &key);
    assert_eq!(trusted.verify(&env).unwrap().task, None);
    // A new one carries them inside the signature: changing them breaks it.
    let mut new = crate::tests::github_queue_task("t-1-a2");
    (new.task, new.attempt) = (Some("t-1".into()), Some(2));
    let env = new.sign(&key).unwrap();
    let back = trusted.verify(&env).unwrap();
    assert_eq!((back.task.as_deref(), back.attempt), (Some("t-1"), Some(2)));
    let mut tampered = env.clone();
    let payload = String::from_utf8(env.payload_bytes().unwrap()).unwrap().replace("\"attempt\":2", "\"attempt\":3");
    tampered.payload = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload);
    assert!(trusted.verify(&tampered).is_err());
}

mod board {
    use super::e2e::world;
    use super::super::sync::sync_repo;
    use crate::tests::github_queue::TOKEN;

    const BOARD: &str = "[[senders]]\naddress = \"github:alice\"\n[projects_v2]\nowner = \"org\"\nnumber = 1\nattempt_field = \"Attempt\"\ntokens_field = \"Tokens\"\n";
    const FORM: &str = "### What should be done?\n\nFix it.\n";

    fn fields(names: &[&str]) -> Vec<(String, Vec<String>)> {
        let mut v = vec![("Status".to_string(), ["Todo", "In Progress", "Done"].map(String::from).to_vec())];
        v.extend(names.iter().map(|n| (n.to_string(), vec![])));
        v
    }

    fn calls(w: &super::e2e::World, what: &str) -> Vec<serde_json::Value> {
        w.fake.state.lock().unwrap().graphql.iter().filter(|g| g["query"].as_str().unwrap_or("").contains(what)).cloned().collect()
    }

    #[test]
    fn the_board_shows_each_task_and_only_changes_are_sent() {
        let w = world("board", BOARD);
        w.fake.state.lock().unwrap().board_fields = fields(&["Attempt", "Tokens"]);
        let req = w.fake.state.lock().unwrap().open_issue("alice", "Fix it", FORM, &["toto:request"]);
        w.pass();
        assert_eq!(calls(&w, "projectV2(number").len(), 1, "ids are looked up once");
        let add = calls(&w, "addProjectV2ItemById");
        assert_eq!(add.len(), 1);
        assert_eq!(add[0]["variables"]["content"], format!("I_{req}"), "the card is the request issue");
        let sets = calls(&w, "updateProjectV2ItemFieldValue");
        let status = sets.iter().find(|s| s["variables"]["field"] == "F_Status").unwrap();
        assert_eq!(status["variables"]["option"], "O_In Progress", "Running shows as GitHub's default In Progress");
        assert!(sets.iter().any(|s| s["variables"]["field"] == "F_Attempt" && s["variables"]["number"] == 1.0));
        assert!(w.task().links.iter().any(|l| l.0 == format!("projects-v2:PVTI_I_{req}")), "{:?}", w.task().links);

        let before = w.fake.state.lock().unwrap().graphql.len();
        w.pass();
        assert_eq!(w.fake.state.lock().unwrap().graphql.len(), before, "an unchanged task is not sent again");

        w.run_attempt(&[("docs/guide.md", "x\n")], "done");
        w.pass();
        assert_eq!(calls(&w, "projectV2(number").len(), 1, "the ids were kept on the state branch");
        let last = calls(&w, "updateProjectV2ItemFieldValue");
        assert!(last.iter().rev().take(3).any(|s| s["variables"]["option"] == "O_In Progress"), "Awaiting feedback falls back to In Progress");
        assert!(last.iter().any(|s| s["variables"]["field"] == "F_Tokens" && s["variables"]["number"] == 42.0));
    }

    #[test]
    fn a_missing_field_is_named_and_does_not_stop_the_pass() {
        let w = world("board-missing", BOARD);
        w.fake.state.lock().unwrap().board_fields = fields(&["Tokens"]);
        w.fake.state.lock().unwrap().open_issue("alice", "Fix it", FORM, &["toto:request"]);
        let r = sync_repo(&w.cfg, &w.work, &w.key, &w.secrets(), chrono::Utc::now()).unwrap();
        assert!(r.errors.iter().any(|e| e.contains("no field named `Attempt`")), "{:?}", r.errors);
        assert_eq!(r.posted.len(), 1, "the board failing does not hold up the work");
        assert!(r.commit.is_some());
        let mut no_token = w.secrets();
        no_token.projects_token = None;
        let e = sync_repo(&w.cfg, &w.work, &w.key, &no_token, chrono::Utc::now()).unwrap_err();
        assert!(e.to_string().contains("TOTO_PROJECTS_TOKEN"), "{e}");
        let _ = TOKEN;
    }
}

mod mail {
    use super::super::email::*;
    use super::super::imap::Imap;
    use super::super::{Received, SignalKind, Verification};
    use std::io::{BufRead, BufReader, Write};

    fn cfg() -> Config {
        toml::from_str("address = \"toto@example.org\"\nimap_host = \"imap.example.org\"\nauthserv_id = \"mx.example.org\"\n").unwrap()
    }

    const TAG: &str = "0123456789abcdef0123456789ABCDEF";

    /// A mail as the inbox's provider would store it.
    pub(super) fn eml(from: &str, to: &str, subject: &str, extra: &str, body: &str) -> Vec<u8> {
        format!("{extra}From: Someone <{from}>\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <{}@mail.example>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n", crate::archive::sha256_hex(format!("{from}{subject}{body}").as_bytes()).get(..12).unwrap())
            .into_bytes()
    }

    pub(super) fn dkim_pass(domain: &str) -> String {
        format!("Authentication-Results: mx.example.org;\r\n\tdkim=pass (2048-bit key) header.d={domain} header.s=s1 header.b=abc;\r\n\tspf=pass smtp.mailfrom={domain}\r\n")
    }

    fn parsed(raw: &[u8]) -> Mail {
        parse(raw, &cfg(), "x").unwrap()
    }

    #[test]
    fn dkim_is_read_from_the_inbox_providers_own_header_only() {
        let ok = parsed(&eml("alice@example.com", "toto@example.org", "hi", &dkim_pass("example.com"), "body"));
        assert!(ok.dkim && ok.addressed && ok.automated.is_none(), "{ok:?}");
        assert!(parsed(&eml("alice@mail.example.com", "toto@example.org", "hi", &dkim_pass("example.com"), "b")).dkim, "relaxed alignment: a subdomain");
        assert!(!parsed(&eml("alice@example.com", "toto@example.org", "hi", &dkim_pass("evil.example"), "b")).dkim, "signed by someone else");
        assert!(!parsed(&eml("alice@example.com", "toto@example.org", "hi", &dkim_pass("ample.com"), "b")).dkim, "a suffix is not a subdomain");
        let fail = "Authentication-Results: mx.example.org; dkim=fail header.d=example.com\r\n";
        assert!(!parsed(&eml("alice@example.com", "toto@example.org", "hi", fail, "b")).dkim);
        // The sender adds a passing header of their own below the provider's: only the topmost counts.
        let forged = format!("{fail}{}", dkim_pass("example.com"));
        assert!(!parsed(&eml("alice@example.com", "toto@example.org", "hi", &forged, "b")).dkim, "an earlier hop's header is not believed");
        let other = "Authentication-Results: mx.attacker.example; dkim=pass header.d=example.com\r\n";
        assert!(!parsed(&eml("alice@example.com", "toto@example.org", "hi", other, "b")).dkim, "another provider's results are not believed");
        let by_i = "Authentication-Results: mx.example.org; dkim=pass header.i=@example.com\r\n";
        assert!(parsed(&eml("alice@example.com", "toto@example.org", "hi", by_i, "b")).dkim);
    }

    #[test]
    fn automated_unaddressed_and_secret_addressed_mail() {
        for (extra, why) in [
            ("Auto-Submitted: auto-replied\r\n", "Auto-Submitted"),
            ("Precedence: bulk\r\n", "Precedence"),
            ("List-Id: <devs.example.com>\r\n", "List-Id"),
        ] {
            let m = parsed(&eml("alice@example.com", "toto@example.org", "Out of office", extra, "away"));
            assert!(m.automated.as_deref().unwrap_or("").contains(why), "{m:?}");
            assert!(matches!(m.received(), Received::Skipped { .. }));
        }
        assert!(parsed(&eml("alice@example.com", "toto@example.org", "x", "Auto-Submitted: no\r\n", "b")).automated.is_none());
        assert!(parsed(&eml("toto@example.org", "toto@example.org", "x", "", "b")).automated.is_some(), "mail from the inbox itself");
        let fwd = parsed(&eml("alice@example.com", "bob@example.com", "x", &dkim_pass("example.com"), "b"));
        assert!(!fwd.addressed && matches!(fwd.received(), Received::Skipped { reason, .. } if reason.contains("To or Cc")));
        let secret = parsed(&eml("bob@example.com", &format!("Toto <toto+{TAG}@example.org>"), "x", "", "b"));
        assert!(secret.addressed);
        assert_eq!(secret.tag_sha256, Some(crate::archive::sha256_hex(TAG.as_bytes())), "the tag as written, hashed");
        assert_eq!(parsed(&eml("bob@example.com", "toto+short@example.org", "x", "", "b")).tag_sha256, None, "short tags are not secrets");
    }

    #[test]
    fn replies_are_threaded_stripped_and_can_end_a_task() {
        let body = "Also the second one.\r\n\r\nOn Tue, 7 Oct 2026 at 09:00, toto <\r\ntoto@example.org> wrote:\r\n> earlier\r\n> text\r\n";
        let reply = parsed(&eml("alice@example.com", "toto@example.org", "Re: [docs] Fix it", "In-Reply-To: <first@mail.example>\r\nReferences: <root@mail.example> <first@mail.example>\r\n", body));
        assert_eq!(reply.body, "Also the second one.");
        assert_eq!(reply.thread.iter().map(|t| t.0.as_str()).collect::<Vec<_>>(), ["mail:first@mail.example", "mail:root@mail.example"]);
        match reply.received() {
            Received::Message { thread: Some(t), author, .. } => {
                assert_eq!(t.0.len(), 2);
                assert_eq!(author.verified, Verification::None);
            }
            other => panic!("{other:?}"),
        }
        let done = parsed(&eml("alice@example.com", "toto@example.org", "Re: x", "In-Reply-To: <first@mail.example>\r\n", "Done.\r\n\r\n-- \r\nAlice"));
        assert!(matches!(done.received(), Received::Signal { kind: SignalKind::Done, .. }));
        let new = parsed(&eml("alice@example.com", "toto@example.org", "done", "", "done"));
        assert!(matches!(new.received(), Received::Message { thread: None, .. }), "\"done\" in a new mail is just a request");
        assert_eq!(strip_quoted("hi\n-----Original Message-----\nold"), "hi");
    }

    /// A scripted IMAP server: UIDVALIDITY 7, messages with UIDs 3 and 5, and UID 6 too large.
    fn imap_server(messages: Vec<(u32, Vec<u8>)>) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let messages = messages.clone();
                std::thread::spawn(move || {
                    let mut w = s.try_clone().unwrap();
                    let mut r = BufReader::new(s);
                    w.write_all(b"* OK ready\r\n").unwrap();
                    let mut line = String::new();
                    while r.read_line(&mut line).unwrap_or(0) > 0 {
                        let l = line.trim_end().to_string();
                        line.clear();
                        let (tag, cmd) = l.split_once(' ').unwrap();
                        let out = if cmd.starts_with("LOGIN") {
                            if cmd == "LOGIN \"toto@example.org\" \"p\\\"w\"" { format!("{tag} OK in\r\n") } else { format!("{tag} NO bad login\r\n") }
                        } else if cmd.starts_with("SELECT") {
                            format!("* 3 EXISTS\r\n* OK [UIDVALIDITY 7] ok\r\n{tag} OK [READ-WRITE] done\r\n")
                        } else if let Some(range) = cmd.strip_prefix("UID SEARCH UID ") {
                            let from: u32 = range.split(':').next().unwrap().parse().unwrap();
                            let mut found: Vec<String> = messages.iter().map(|m| m.0).chain([6]).filter(|u| *u >= from).map(|u| u.to_string()).collect();
                            if found.is_empty() {
                                found.push("6".into()); // n:* always matches the last message
                            }
                            format!("* SEARCH {}\r\n{tag} OK done\r\n", found.join(" "))
                        } else if let Some(rest) = cmd.strip_prefix("UID FETCH ") {
                            let uid: u32 = rest.split(' ').next().unwrap().parse().unwrap();
                            let msg = messages.iter().find(|m| m.0 == uid).map(|m| m.1.clone());
                            if rest.contains("RFC822.SIZE") {
                                let size = msg.as_ref().map_or(20_000_000, Vec::len);
                                format!("* 1 FETCH (UID {uid} RFC822.SIZE {size})\r\n{tag} OK done\r\n")
                            } else {
                                let m = msg.unwrap();
                                let mut out = format!("* 1 FETCH (UID {uid} BODY[] {{{}}}\r\n", m.len()).into_bytes();
                                out.extend_from_slice(&m);
                                out.extend_from_slice(format!(")\r\n{tag} OK done\r\n").as_bytes());
                                w.write_all(&out).unwrap();
                                continue;
                            }
                        } else if cmd == "LOGOUT" {
                            let _ = w.write_all(format!("* BYE\r\n{tag} OK bye\r\n").as_bytes());
                            return;
                        } else {
                            format!("{tag} BAD what\r\n")
                        };
                        w.write_all(out.as_bytes()).unwrap();
                    }
                });
            }
        });
        port
    }

    #[test]
    fn the_imap_client_reads_new_mail_by_uid() {
        let a = eml("alice@example.com", "toto@example.org", "one", "", "first {5}\r\n) tricky");
        let b = eml("alice@example.com", "toto@example.org", "two", "", "second");
        let port = imap_server(vec![(3, a.clone()), (5, b.clone())]);
        let imap = Imap { host: "127.0.0.1".into(), port, user: "toto@example.org".into(), password: "p\"w".into(), folder: "INBOX".into(), plaintext: true };
        let f = imap.fetch(None, 0, 10).unwrap();
        assert_eq!(f.validity, 7);
        assert_eq!(f.messages, vec![(3, a.clone()), (5, b.clone())], "literals are read byte for byte");
        assert_eq!(f.too_large, [6], "an oversized message is skipped, not fetched");
        assert_eq!(imap.fetch(Some(7), 3, 10).unwrap().messages, vec![(5, b.clone())]);
        assert!(imap.fetch(Some(7), 6, 10).unwrap().messages.is_empty(), "n:* matching the last message is not new mail");
        assert_eq!(imap.fetch(Some(6), 5, 10).unwrap().messages.len(), 2, "a new UIDVALIDITY starts over");
        assert_eq!(imap.fetch(None, 0, 1).unwrap().messages.len(), 1, "at most max per pass");
        let wrong = Imap { password: "nope".into(), ..imap };
        assert!(wrong.fetch(None, 0, 10).unwrap_err().to_string().contains("LOGIN"));
    }
}

mod mail_flow {
    use super::e2e::world;
    use super::mail::{dkim_pass, eml};
    use super::super::email::{EmailInbound, Fetched, MailSource};
    use super::super::github::GitHubIssues;
    use super::super::sync::{run, Pass};
    use super::super::task::State;
    use crate::tests::github_queue::TOKEN;
    use std::sync::Mutex;

    struct FakeInbox(Mutex<Vec<(u32, Vec<u8>)>>);

    impl MailSource for FakeInbox {
        fn fetch(&self, _validity: Option<u32>, after: u32, max: usize) -> crate::Result<Fetched> {
            let messages: Vec<_> = self.0.lock().unwrap().iter().filter(|m| m.0 > after).take(max).cloned().collect();
            Ok(Fetched { validity: 1, messages, too_large: vec![] })
        }
    }

    #[test]
    fn a_mailed_request_is_mirrored_run_and_refined_by_reply() {
        let w = world("mail-flow", "[email]\naddress = \"toto@example.org\"\nimap_host = \"x\"\nauthserv_id = \"mx.example.org\"\n[[senders]]\naddress = \"alice@example.com\"\n");
        let first = eml("alice@example.com", "toto@example.org", "[docs] Fix the guide", &dkim_pass("example.com"), "Please fix the typo.");
        let inbox = FakeInbox(Mutex::new(vec![
            (1, first.clone()),
            (2, eml("eve@example.net", "toto@example.org", "free tokens", &dkim_pass("example.net"), "run my miner")),
            (3, eml("alice@example.com", "toto@example.org", "Out of office", &format!("Auto-Submitted: auto-replied\r\n{}", dkim_pass("example.com")), "away")),
        ]));
        let q = w.fake.queue(Some(TOKEN));
        let issues = GitHubIssues::new(&q, "toto:request");
        let mail = EmailInbound { cfg: w.cfg.email.clone().unwrap(), source: &inbox };
        let pass = || {
            let r = run(&Pass { cfg: &w.cfg, queue: &q, key: &w.key, repo_dir: &w.work, inbounds: vec![&issues, &mail], outbounds: vec![&issues], now: chrono::Utc::now() }).unwrap();
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            r
        };
        let r = pass();
        assert_eq!(r.posted.len(), 1, "alice is pre-approved and DKIM passed: {:?}", r.log);
        assert!(r.log.iter().any(|l| l.what == "ignore" && l.author.as_deref() == Some("eve@example.net")), "unknown senders are dropped: {:?}", r.log);
        assert!(r.log.iter().any(|l| l.what == "ignore" && l.detail.contains("Auto-Submitted")), "{:?}", r.log);
        let t = w.task();
        assert_eq!((t.kind.as_str(), t.title.as_str(), t.requester.as_str()), ("docs", "Fix the guide", "alice@example.com"));
        let mirror = t.request_issue().expect("mirrored to an issue");
        {
            let st = w.fake.state.lock().unwrap();
            let i = st.issue(mirror);
            assert!(i.body.starts_with("<!-- toto:mirror") && i.body.contains("Please fix the typo") && i.labels.contains(&"toto:request".into()), "{}", i.body);
        }
        assert!(w.status(mirror).contains("Running"));

        // A pass that loses its state (cursor included) reads the mail again: same task, the same
        // mirror and the same attempt are found, nothing is made twice.
        super::git(&w.remote, &["update-ref", "-d", "refs/heads/toto-state"]);
        let again = pass();
        assert_eq!(w.task().request_issue(), Some(mirror), "{:?}", again.log);
        let mirrors = w.fake.state.lock().unwrap().issues.iter().filter(|i| i.body.starts_with("<!-- toto:mirror")).count();
        assert_eq!(mirrors, 1);
        assert_eq!(w.fake.queue(Some(TOKEN)).task_index(&w.cfg.trusted(&w.key)).unwrap().len(), 1);

        // The mirror is not a new request; a reply by mail refines the task; so does a comment on
        // the mirror.
        w.run_attempt(&[("docs/guide.md", "fixed\n")], "ok");
        let first_id = String::from_utf8_lossy(&first).lines().find_map(|l| l.strip_prefix("Message-ID: ").map(String::from)).unwrap();
        inbox.0.lock().unwrap().push((4, eml("alice@example.com", "toto@example.org", "Re: [docs] Fix the guide", &format!("In-Reply-To: {first_id}\r\n{}", dkim_pass("example.com")), "Also the install page.\r\n\r\n> quoted")));
        let r = pass();
        assert_eq!(w.tasks().len(), 1, "{:?}", r.log);
        let t = w.task();
        assert_eq!(t.state, State::Running { attempt: 2 }, "{:?}", r.log);
        assert_eq!(t.conversation.iter().filter(|c| c.role == super::super::task::Role::Refinement).map(|c| c.text.as_str()).collect::<Vec<_>>(), ["Also the install page."]);

        // A reply that says done ends it.
        w.run_attempt(&[("docs/install.md", "x\n")], "ok");
        inbox.0.lock().unwrap().push((5, eml("alice@example.com", "toto@example.org", "Re: x", &format!("In-Reply-To: {first_id}\r\n{}", dkim_pass("example.com")), "done")));
        pass();
        assert_eq!(w.task().state, State::Done);
        assert!(w.fake.state.lock().unwrap().issue(mirror).closed);
    }
}

#[test]
fn the_example_intake_config_is_valid() {
    let c = super::sync::IntakeConfig::parse(include_str!("../../docs/examples/project/.toto/intake.toml")).unwrap();
    assert_eq!((c.project_id.as_str(), c.policy.default_kind(), c.policy.senders.len()), ("acme-docs", "docs".to_string(), 2));
    let form = include_str!("../../docs/examples/project/.github/ISSUE_TEMPLATE/toto-task.yml");
    for kind in c.policy.kinds.keys() {
        assert!(form.contains(&format!("- {kind}\n")), "the issue form offers `{kind}`");
    }
    assert!(super::sync::IntakeConfig::parse("project_id = \"a\"\nrepo = \"a/b\"\nstate_branch = \"main\"\n[kinds.x]\nestimate = 1").is_err());
}
