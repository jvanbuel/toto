//! A GitHub Projects (v2) board as an [`Outbound`]: each task's request issue is a card, with its
//! Status set from the task's state, and optional number fields for the attempt and the tokens used.
//!
//! Projects v2 has only a GraphQL API, and the workflow's own `GITHUB_TOKEN` cannot reach it: the
//! board needs a fine-grained token or a GitHub App with the `project` scope (`token_env`). The
//! board only displays state; moving a card does nothing in v1.

use super::task::State;
use super::{ItemRef, Outbound, TaskView};
use crate::github_queue::GitHubQueue;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Mutex;

fn d_token_env() -> String {
    "TOTO_PROJECTS_TOKEN".into()
}
fn d_status() -> String {
    "Status".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The organisation (or user, with `owner_is_user`) that owns the board.
    pub owner: String,
    #[serde(default)]
    pub owner_is_user: bool,
    /// The board's number, from its URL.
    pub number: u64,
    /// Environment variable holding a token with the `project` scope.
    #[serde(default = "d_token_env")]
    pub token_env: String,
    #[serde(default = "d_status")]
    pub status_field: String,
    /// A number field for the latest attempt, if the board has one.
    #[serde(default)]
    pub attempt_field: Option<String>,
    /// A number field for the tokens used, if the board has one.
    #[serde(default)]
    pub tokens_field: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Ids {
    project: String,
    status: String,
    options: BTreeMap<String, String>,
    attempt: Option<String>,
    tokens: Option<String>,
}

pub struct ProjectsV2<'a> {
    cfg: Config,
    /// The board's API client (its own token).
    board: GitHubQueue,
    /// The queue repository, to find an issue's node id.
    repo: &'a GitHubQueue,
    ids: Mutex<Option<Ids>>,
}

/// Status options to use for a state, in order of preference; the first the board has wins.
/// GitHub's default board (Todo, In Progress, Done) works without changes.
pub fn status_options(state: &State) -> &'static [&'static str] {
    match state {
        State::Draft => &["Awaiting approval", "Queued", "Todo"],
        State::Queued => &["Queued", "Todo"],
        State::Running { .. } => &["Running", "In progress", "In Progress"],
        State::AwaitingFeedback { .. } => &["Awaiting feedback", "In review", "In Review", "In progress", "In Progress"],
        State::Done => &["Done"],
        State::Cancelled => &["Cancelled", "Done"],
    }
}

const LOOKUP: &str = "query($login: String!, $number: Int!) { owner: OWNER(login: $login) { projectV2(number: $number) { id fields(first: 100) { nodes { ... on ProjectV2FieldCommon { id name } ... on ProjectV2SingleSelectField { options { id name } } } } } } }";
const ADD: &str = "mutation($project: ID!, $content: ID!) { addProjectV2ItemById(input: {projectId: $project, contentId: $content}) { item { id } } }";
const SET_OPTION: &str = "mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) { updateProjectV2ItemFieldValue(input: {projectId: $project, itemId: $item, fieldId: $field, value: {singleSelectOptionId: $option}}) { projectV2Item { id } } }";
const SET_NUMBER: &str = "mutation($project: ID!, $item: ID!, $field: ID!, $number: Float!) { updateProjectV2ItemFieldValue(input: {projectId: $project, itemId: $item, fieldId: $field, value: {number: $number}}) { projectV2Item { id } } }";

impl<'a> ProjectsV2<'a> {
    /// `board` must carry a token with the `project` scope.
    pub fn new(cfg: Config, board: GitHubQueue, repo: &'a GitHubQueue) -> Self {
        Self { cfg, board, repo, ids: Mutex::default() }
    }

    fn lookup(&self) -> Result<Ids> {
        let q = LOOKUP.replace("OWNER", if self.cfg.owner_is_user { "user" } else { "organization" });
        let data = self.board.graphql(&q, json!({"login": self.cfg.owner, "number": self.cfg.number}))?;
        let project = &data["owner"]["projectV2"];
        let id = project["id"].as_str().ok_or_else(|| Error::Queue(format!("Projects board {}/{} not found, or the token cannot see it (it needs the `project` scope)", self.cfg.owner, self.cfg.number)))?;
        let fields = project["fields"]["nodes"].as_array().cloned().unwrap_or_default();
        let field = |name: &str| fields.iter().find(|f| f["name"].as_str() == Some(name));
        let missing = |name: &str| Error::Queue(format!("the Projects board has no field named `{name}`: create it, or change the name in .toto/intake.toml"));
        let status = field(&self.cfg.status_field).ok_or_else(|| missing(&self.cfg.status_field))?;
        let options = status["options"].as_array().into_iter().flatten().filter_map(|o| Some((o["name"].as_str()?.to_string(), o["id"].as_str()?.to_string()))).collect();
        let number = |name: &Option<String>| -> Result<Option<String>> {
            match name {
                None => Ok(None),
                Some(n) => Ok(Some(field(n).and_then(|f| f["id"].as_str()).ok_or_else(|| missing(n))?.to_string())),
            }
        };
        Ok(Ids {
            project: id.into(),
            status: status["id"].as_str().unwrap_or_default().into(),
            options,
            attempt: number(&self.cfg.attempt_field)?,
            tokens: number(&self.cfg.tokens_field)?,
        })
    }

    fn ids(&self) -> Result<Ids> {
        let mut g = self.ids.lock().unwrap();
        if g.is_none() {
            *g = Some(self.lookup()?);
        }
        Ok(g.clone().expect("set"))
    }

    fn set(&self, ids: &Ids, item: &str, v: &TaskView) -> Result<()> {
        let wanted = status_options(&v.state);
        let option = wanted.iter().find_map(|n| ids.options.get(*n)).ok_or_else(|| Error::Queue(format!("the `{}` field has no option named {}: add one", self.cfg.status_field, wanted.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(" or "))))?;
        self.board.graphql(SET_OPTION, json!({"project": ids.project, "item": item, "field": ids.status, "option": option}))?;
        for (field, n) in [(&ids.attempt, f64::from(v.attempt)), (&ids.tokens, v.tokens_used as f64)] {
            if let Some(f) = field {
                self.board.graphql(SET_NUMBER, json!({"project": ids.project, "item": item, "field": f, "number": n}))?;
            }
        }
        Ok(())
    }
}

impl Outbound for ProjectsV2<'_> {
    fn name(&self) -> &str {
        "projects-v2"
    }

    fn publish(&self, v: &TaskView) -> Result<Option<ItemRef>> {
        // The card is the request issue; a request from elsewhere gets one from the issues outbound.
        let Some(issue) = v.request_issue() else { return Ok(None) };
        let content = self.repo.issue(issue)?.node_id;
        let attempt = |ids: &Ids| -> Result<String> {
            let added = self.board.graphql(ADD, json!({"project": ids.project, "content": content}))?;
            let item = added["addProjectV2ItemById"]["item"]["id"].as_str().ok_or_else(|| Error::Queue("Projects: no item id returned".into()))?.to_string();
            self.set(ids, &item, v)?;
            Ok(item)
        };
        let item = match attempt(&self.ids()?) {
            Ok(item) => item,
            Err(_) => {
                // Cached ids go stale when the board changes: look them up again, once.
                *self.ids.lock().unwrap() = None;
                attempt(&self.ids()?)?
            }
        };
        Ok(Some(ItemRef::new(format!("projects-v2:{item}"))))
    }

    fn cache(&self) -> Option<serde_json::Value> {
        self.ids.lock().unwrap().as_ref().and_then(|i| serde_json::to_value(i).ok())
    }

    fn restore(&self, cache: serde_json::Value) {
        if let Ok(ids) = serde_json::from_value::<Ids>(cache) {
            *self.ids.lock().unwrap() = Some(ids);
        }
    }
}
