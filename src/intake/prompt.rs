//! The prompt of an attempt: the original request, every refinement in order, and what earlier
//! attempts produced. The agent's standing instructions come from the project's own agent directory
//! (`.toto/agent`); this is only the task. Everything people wrote is fenced: it is data for the
//! agent to act on, never configuration.

use super::task::{Role, Task};
use crate::pr_flow::fenced;

/// Builds the prompt for attempt `n` from the task's conversation. When it is longer than
/// `max_chars`, the oldest results are dropped first; requests and refinements are always kept.
pub fn build(task: &Task, n: u32, max_chars: usize) -> String {
    let head = if n == 1 {
        format!("Task `{}` ({}): {}\n\nThe workspace is a checkout of the project's default branch. Do what the request below asks.", task.id, task.kind, task.title)
    } else {
        format!(
            "Task `{}` ({}): {}\n\nThis is attempt {n}. The workspace already contains the changes earlier attempts made (the task's branch). The people who asked have reviewed them and refined the request: do what the refinements ask, keeping what was right.",
            task.id, task.kind, task.title
        )
    };
    // Sections in conversation order; results can be dropped, requests cannot.
    let mut sections: Vec<(bool, String)> = vec![];
    let mut attempt = 0;
    for t in &task.conversation {
        match t.role {
            Role::Request => sections.push((false, format!("## Request from {}\n\n{}", t.author, fenced(&t.text, 20_000)))),
            Role::Refinement => sections.push((false, format!("## Refinement from {}\n\n{}", t.author, fenced(&t.text, 20_000)))),
            Role::Result => {
                attempt += 1;
                sections.push((true, format!("## What attempt {attempt} reported\n\n{}", fenced(&t.text, 8_000))));
            }
        }
    }
    let len = |s: &[(bool, String)]| head.len() + s.iter().map(|x| x.1.len() + 2).sum::<usize>();
    while len(&sections) > max_chars {
        let Some(i) = sections.iter().position(|s| s.0) else { break };
        sections.remove(i);
    }
    let mut out = head;
    for (_, s) in sections {
        out.push_str("\n\n");
        out.push_str(&s);
    }
    out
}
