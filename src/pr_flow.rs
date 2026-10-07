//! Project side: turns verified results into pull requests, automatically (`toto results-to-pr`).
//!
//! Contributors only offer tokens; they never see the project. The project's own automation (a
//! scheduled GitHub Action, `docs/github-queue.md`) calls this. It never trusts a result more than a
//! contributor's patch: the project's own signature on the task and the runner's on the result are
//! verified, paths are validated and protected paths are refused (a model must not be able to edit
//! CI workflows), the number of open toto PRs is capped, and the model's output is only ever shown
//! inside a code fence. Review and merge are the project's usual PR process.

use crate::archive::{valid_path, Record};
use crate::github_queue::{handled_comment, handled_comment_pr, Finished, GitHubQueue};
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Paths a result may never touch: they run code with the project's privileges.
pub const DEFAULT_PROTECTED: [&str; 7] = [".git/", ".github/", ".gitlab/", ".gitlab-ci.yml", ".gitmodules", "CODEOWNERS", ".githooks/"];

pub struct Options {
    /// A checkout of the project repository with push access to `origin`.
    pub repo_dir: PathBuf,
    pub base: String,
    pub branch_prefix: String,
    pub protected: Vec<String>,
    /// Stop opening PRs while this many toto PRs are open (later attempts on an open one still land).
    pub max_open: usize,
    /// The request issue of each task, for `Closes #<n>` in its pull request.
    pub closes: std::collections::BTreeMap<String, u64>,
    /// A title for each task's pull request.
    pub titles: std::collections::BTreeMap<String, String>,
    pub git_name: String,
    pub git_email: String,
}

impl Options {
    pub fn new(repo_dir: impl Into<PathBuf>, base: &str) -> Self {
        Self {
            repo_dir: repo_dir.into(),
            base: base.into(),
            branch_prefix: "toto/".into(),
            protected: DEFAULT_PROTECTED.map(String::from).to_vec(),
            max_open: 10,
            closes: Default::default(),
            titles: Default::default(),
            git_name: "toto".into(),
            git_email: "toto@users.noreply.github.com".into(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    PullRequest { task: String, number: u64 },
    TextOnly(String),
    NoChange(String),
    Refused { task: String, why: String },
    Deferred(String),
    AlreadyHandled(String),
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git").current_dir(dir).args(args).output()?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(Error::Queue(format!("git {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim())))
    }
}

fn protected_hit<'a>(records: &'a [Record], protected: &[String]) -> Option<&'a str> {
    records.iter().map(|r| match r {
        Record::File { path, .. } | Record::Deleted { path } => path.as_str(),
    }).find(|p| {
        // Case-insensitive: on a case-insensitive filesystem `.GITHUB/` is `.github/`.
        let lower = p.to_lowercase();
        protected.iter().map(|x| x.to_lowercase()).any(|x| if x.ends_with('/') { lower.starts_with(&x) } else { lower == x })
    })
}

/// Writes the records into the checkout, replacing files and applying deletions. Only the exec bit
/// of the mode is kept; symlinks are never followed or created.
fn apply(root: &Path, records: &[Record]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let canon = root.canonicalize()?;
    let bad = |m: String| Error::Schema(m);
    for r in records {
        match r {
            Record::File { path, mode, data } => {
                if !valid_path(path) {
                    return Err(bad(format!("unsafe path `{path}`")));
                }
                let target = canon.join(path);
                std::fs::create_dir_all(target.parent().ok_or_else(|| bad("no parent".into()))?)?;
                if !target.parent().unwrap().canonicalize()?.starts_with(&canon) {
                    return Err(bad(format!("`{path}` escapes the repository")));
                }
                if std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink() || m.is_dir()) {
                    return Err(bad(format!("`{path}` is a symlink or directory in the repository")));
                }
                std::fs::write(&target, data)?;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(if mode & 0o111 != 0 { 0o755 } else { 0o644 }))?;
            }
            Record::Deleted { path } => {
                if !valid_path(path) {
                    return Err(bad(format!("unsafe path `{path}`")));
                }
                let target = canon.join(path);
                if std::fs::symlink_metadata(&target).is_ok_and(|m| m.is_file() || m.file_type().is_symlink()) {
                    std::fs::remove_file(target)?;
                }
            }
        }
    }
    Ok(())
}

/// Wraps untrusted text in a code fence it cannot close, truncated to `max` characters.
pub fn fenced(text: &str, max: usize) -> String {
    let shown: String = text.chars().take(max).collect();
    let longest = shown.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat((longest + 1).max(3));
    let more = if text.chars().count() > max { "\n… (truncated)" } else { "" };
    format!("{fence}text\n{shown}{more}\n{fence}")
}

fn provenance(f: &Finished, repo: &str) -> Result<String> {
    let r = f.result.open()?;
    Ok(format!(
        "Result for task `{}` (`{}`, project `{}`), from issue #{} in {repo}.\n\n| | |\n|---|---|\n| runner | `{}` |\n| tokens used | {} |\n| output sha256 | `{}` |\n| artifacts sha256 | `{}` |\n\nThe runner's signature, the project's signature on the task and both hashes were verified before this was opened. Review it like any contribution; the files below were produced by a model.",
        f.manifest.id, f.manifest.kind, f.manifest.project_id, f.issue, r.runner_id, r.tokens_used, r.output_hash, r.artifacts_hash.as_deref().unwrap_or("none"),
    ))
}

/// Handles every finished task: opens a PR for results with file changes, comments the output for
/// text-only results, and records what it did on the issue so nothing is done twice. A result that
/// is itself bad (unsafe paths, a path that is a symlink) is refused and noted on its issue; an
/// infrastructure failure (network, git push) aborts the run so the next one retries.
pub fn run(q: &GitHubQueue, repo: &str, trusted: &crate::manifest::TrustedProjects, o: &Options) -> Result<Vec<Outcome>> {
    let mut out = vec![];
    let mut open = q.open_pulls_with_prefix(&o.branch_prefix)?;
    for f in q.open_results(trusted)? {
        let (id, issue) = (f.manifest.id.clone(), f.issue);
        match handle(q, repo, &f, o, &mut open) {
            Ok(outcome) => out.push(outcome),
            Err(Error::Schema(why)) => {
                let runner = f.result.open().map(|b| b.runner_id).unwrap_or_default();
                let _ = q.comment(issue, &handled_comment("skip", &id, &runner, &format!("Not turned into a pull request: {why}.")));
                out.push(Outcome::Refused { task: id, why });
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

fn handle(q: &GitHubQueue, repo: &str, f: &Finished, o: &Options, open: &mut usize) -> Result<Outcome> {
    let id = f.manifest.id.clone();
    if f.handled {
        return Ok(Outcome::AlreadyHandled(id));
    }
    let body = f.result.open()?;
    let runner = body.runner_id.clone();
    let records = f.result.artifact_records(f.manifest.output_schema.max_artifact_bytes.max(1))?;
    let info = provenance(f, repo)?;

    if records.is_empty() {
        q.comment(f.issue, &handled_comment("pr", &id, &runner, &format!("{info}\n\nThis result has no file changes. Output:\n\n{}", fenced(&body.output, 6000))))?;
        q.close_issue(f.issue)?;
        return Ok(Outcome::TextOnly(id));
    }
    if let Some(path) = protected_hit(&records, &o.protected) {
        let why = format!("touches the protected path `{path}`");
        q.comment(f.issue, &handled_comment("skip", &id, &runner, &format!("{info}\n\nNot turned into a pull request: the result {why}. A maintainer can apply it by hand.")))?;
        return Ok(Outcome::Refused { task: id, why });
    }
    // One branch and one pull request per task (ADR 16): each attempt is a commit on it. A
    // standalone manifest is a task of one attempt.
    let task = f.manifest.task.clone().unwrap_or_else(|| id.clone());
    let attempt = f.manifest.attempt.unwrap_or(1);
    let branch = format!("{}{task}", o.branch_prefix);
    let existing = q.open_pull_for(&branch)?;
    if existing.is_none() && *open >= o.max_open {
        return Ok(Outcome::Deferred(id));
    }
    if existing.is_none() && f.manifest.task.is_none() && q.pull_exists(&branch)? {
        q.comment(f.issue, &handled_comment("pr", &id, &runner, "A pull request for this result already exists."))?;
        return Ok(Outcome::AlreadyHandled(id));
    }

    let msg = format!("toto: {task} attempt {attempt} ({})\n\nTask {id} from issue #{}, runner {runner}.\n\nToto-Attempt: {id}", f.manifest.kind, f.issue);
    if !commit_records(&o.repo_dir, &branch, &records, &msg, &id, o)? {
        q.comment(f.issue, &handled_comment("pr", &id, &runner, &format!("{info}\n\nThe result changes nothing in `{}`.", o.base)))?;
        q.close_issue(f.issue)?;
        return Ok(Outcome::NoChange(id));
    }

    let files: Vec<String> = records.iter().map(|r| match r {
        Record::File { path, .. } => format!("- modified or added `{path}`"),
        Record::Deleted { path } => format!("- deleted `{path}`"),
    }).collect();
    let details = format!("{info}\n\n**Changes**\n{}\n\n**Model output**\n\n{}", files.join("\n"), fenced(&body.output, 4000));
    let number = match existing {
        Some(n) => {
            // Later attempts land on the same pull request; say so once per attempt.
            let mark = format!("<!-- toto:attempt task={id} -->");
            if !q.issue_comments(n)?.iter().any(|c| c.body.starts_with(&mark)) {
                q.comment(n, &format!("{mark}\n**Attempt {attempt}** is on this branch now.\n\n{details}"))?;
            }
            n
        }
        None => {
            let closes = o.closes.get(&task).map_or(String::new(), |n| format!("Closes #{n}\n\n"));
            let title = o.titles.get(&task).map_or_else(|| format!("[toto] {}: {task}", f.manifest.kind), |t| format!("[toto] {t}"));
            let n = q.open_pull(&branch, &o.base, &title, &format!("{closes}{details}\n\n<!-- toto:pr task={id} runner={runner} -->"))?;
            *open += 1;
            n
        }
    };
    q.comment(f.issue, &handled_comment_pr(&id, &runner, number, &format!("Applied to pull request #{number}.")))?;
    q.close_issue(f.issue)?;
    Ok(Outcome::PullRequest { task: id, number })
}

/// Commits `records` on top of `branch` (or of the base branch when it does not exist yet) and
/// pushes it. An attempt already on the branch (its `Toto-Attempt` trailer) is not applied again.
/// Returns whether the branch carries the attempt's changes.
fn commit_records(dir: &Path, branch: &str, records: &[Record], msg: &str, id: &str, o: &Options) -> Result<bool> {
    if !git(dir, &["status", "--porcelain"])?.is_empty() {
        return Err(Error::Queue(format!("{} has uncommitted changes; refusing to switch branches in it", dir.display())));
    }
    let origin_base = format!("origin/{}", o.base);
    git(dir, &["fetch", "-q", "origin", &o.base])?;
    let start = if crate::intake::git::remote_has(dir, branch)? {
        git(dir, &["fetch", "-q", "origin", &format!("+refs/heads/{branch}:refs/remotes/origin/{branch}")])?;
        let start = format!("origin/{branch}");
        if git(dir, &["log", "--format=%B", &start, &format!("^{origin_base}")])?.lines().any(|l| l.trim() == format!("Toto-Attempt: {id}")) {
            return Ok(true);
        }
        start
    } else {
        origin_base.clone()
    };
    git(dir, &["checkout", "-q", "--detach", &start])?;
    git(dir, &["checkout", "-q", "-B", branch, &start])?;
    let work = (|| -> Result<bool> {
        apply(dir, records)?;
        let paths = |deleted: bool| -> Vec<&str> {
            records.iter().filter_map(|r| match r {
                Record::File { path, .. } if !deleted => Some(path.as_str()),
                Record::Deleted { path } if deleted => Some(path.as_str()),
                _ => None,
            }).collect()
        };
        for (cmd, list) in [(vec!["add", "--"], paths(false)), (vec!["rm", "-q", "--ignore-unmatch", "--"], paths(true))] {
            if !list.is_empty() {
                git(dir, &[cmd, list].concat())?;
            }
        }
        if Command::new("git").current_dir(dir).args(["diff", "--cached", "--quiet"]).status()?.success() {
            return Ok(false);
        }
        git(dir, &["-c", &format!("user.name={}", o.git_name), "-c", &format!("user.email={}", o.git_email), "commit", "-q", "-m", msg])?;
        git(dir, &["push", "-q", "origin", branch])?;
        Ok(true)
    })();
    // Leave the checkout clean whatever happened.
    let _ = git(dir, &["reset", "-q", "--hard"]);
    let _ = git(dir, &["clean", "-q", "-fd"]); // the tree was clean before, so only our files go
    let _ = git(dir, &["checkout", "-q", "--detach", &origin_base]);
    let _ = git(dir, &["branch", "-q", "-D", branch]);
    work
}
