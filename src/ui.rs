//! `toto ui`: the daemon's local page, served on loopback from the toto binary.
//!
//! A contributor reads here what the CLI prints: status and the pause reason, today's usage
//! against the cap, the audit tail, the projects with what was approved for each, and the diff
//! an update would bring. The actions are the CLI's, through the same previews
//! (`projects::preview_add`, `preview_update`): nothing is approved that was not shown first.
//!
//! The page is a prerendered SvelteKit build embedded at compile time (`ui/build`). The server
//! binds loopback only and every API call must carry the random token printed at start in the
//! `x-toto-token` header: a page on another origin cannot read the token, and a plain form
//! cannot set the header, so other sites in the same browser cannot drive the runner.

use crate::config::Config;
use crate::projects::{self, AddOptions, Preview, UpdateCheck};
use crate::{Error, Result};
use axum::extract::{Path as AxPath, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(rust_embed::RustEmbed)]
#[folder = "ui/build/"]
struct Assets;

pub const TOKEN_HEADER: &str = "x-toto-token";

/// What a confirmation applies: a preview the contributor has seen.
enum Pending {
    Add { preview: Box<Preview>, share: u32 },
    Update { id: String, approval: Box<projects::Approval> },
}

pub struct UiState {
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub token: String,
    /// GitHub API origin for project reads (the directory's, which is the same GitHub).
    pub api: String,
    pending: Mutex<HashMap<String, Pending>>,
}

impl UiState {
    pub fn new(config_path: PathBuf, token: String) -> Result<Self> {
        let cfg = Config::load(&config_path)?;
        Ok(Self { config_path, state_dir: cfg.state_dir.clone(), token, api: cfg.directory.api_url.clone(), pending: Mutex::new(HashMap::new()) })
    }

    fn config(&self) -> Result<Config> {
        Config::load(&self.config_path)
    }

    fn remember(&self, p: Pending) -> String {
        let id = hex::encode(&crate::manifest::generate_key().to_bytes()[..16]);
        self.pending.lock().unwrap().insert(id.clone(), p);
        id
    }
}

/// A random token (tests); the daemon and `toto ui` share the one in the state directory.
pub fn new_token() -> String {
    hex::encode(crate::manifest::generate_key().to_bytes())
}

struct ApiError(StatusCode, String);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        let status = match &e {
            Error::Policy(_) | Error::Verify(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(status, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

#[derive(Serialize)]
pub struct Overview {
    pub status: Option<crate::daemon::Status>,
    pub used_today: u64,
    pub daily_token_cap: u64,
    pub reserve_pct: u64,
    pub projects: usize,
    pub audit: Vec<crate::audit::AuditEntry>,
    pub config_path: String,
}

async fn overview(State(s): State<Arc<UiState>>) -> ApiResult<Overview> {
    let cfg = s.config()?;
    let audit = crate::audit::AuditLog::new(cfg.state_dir.join("audit.jsonl"));
    let used_today = audit.usage_on(chrono::Local::now().date_naive())?.values().sum();
    let mut entries = audit.entries()?;
    let tail = entries.len().saturating_sub(100);
    let mut audit_tail = entries.split_off(tail);
    audit_tail.reverse();
    Ok(Json(Overview {
        status: crate::daemon::Status::read(&cfg.state_dir),
        used_today,
        daily_token_cap: cfg.policy.daily_token_cap,
        reserve_pct: cfg.policy.reserve_pct,
        projects: cfg.projects.len(),
        audit: audit_tail,
        config_path: s.config_path.display().to_string(),
    }))
}

#[derive(Serialize)]
pub struct ProjectView {
    pub id: String,
    pub key: String,
    pub share: u32,
    pub source: Option<String>,
    pub approval: Option<ApprovalView>,
}

#[derive(Serialize)]
pub struct ApprovalView {
    pub image: String,
    pub pinned: String,
    pub short: String,
    pub commit: Option<String>,
    pub prebuilt: bool,
    pub agent_hash: String,
    pub harness: String,
    pub model: Option<String>,
    pub needs_network: bool,
    pub nested_sandbox: bool,
    pub skills: Vec<String>,
    pub mcp: Vec<(String, String)>,
    pub egress_rules: Vec<String>,
    pub describe: Vec<String>,
}

fn approval_view(a: &projects::Approval) -> ApprovalView {
    ApprovalView {
        image: a.image.clone(),
        pinned: a.pinned(),
        short: a.info.short(),
        commit: a.commit.clone(),
        prebuilt: a.prebuilt,
        agent_hash: a.agent_hash.clone(),
        harness: a.agent.harness.clone(),
        model: a.agent.model.clone(),
        needs_network: a.agent.needs_network,
        nested_sandbox: a.agent.needs_nested_sandbox(),
        skills: a.agent.skills.clone(),
        mcp: a.agent.mcp.clone(),
        egress_rules: a.agent.egress_rules.clone(),
        describe: a.describe(),
    }
}

fn project_view(cfg: &Config, id: &str, key: &str) -> ProjectView {
    ProjectView {
        id: id.to_string(),
        key: key.to_string(),
        share: cfg.policy.project_shares.get(id).copied().unwrap_or(0),
        source: cfg.sources.get(id).cloned(),
        approval: cfg.environments.get(id).map(approval_view),
    }
}

async fn list_projects(State(s): State<Arc<UiState>>) -> ApiResult<Vec<ProjectView>> {
    let cfg = s.config()?;
    Ok(Json(cfg.projects.iter().map(|(id, key)| project_view(&cfg, id, key)).collect()))
}

#[derive(Serialize)]
pub struct ProjectDetail {
    #[serde(flatten)]
    pub project: ProjectView,
    pub config_yaml: Option<String>,
    pub files: Vec<String>,
}

async fn project(State(s): State<Arc<UiState>>, AxPath(id): AxPath<String>) -> ApiResult<ProjectDetail> {
    let cfg = s.config()?;
    let key = cfg.projects.get(&id).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("project `{id}` is not configured")))?;
    let files = match cfg.environments.get(&id) {
        Some(a) => crate::agent::unpack(&a.agent_tar_bytes()?)?,
        None => Default::default(),
    };
    Ok(Json(ProjectDetail {
        project: project_view(&cfg, &id, key),
        config_yaml: files.get("config.yaml").map(|b| String::from_utf8_lossy(b).to_string()),
        files: files.keys().cloned().collect(),
    }))
}

#[derive(Deserialize)]
pub struct PreviewRequest {
    pub arg: String,
    #[serde(default = "one")]
    pub share: u32,
}

fn one() -> u32 {
    1
}

#[derive(Serialize)]
pub struct PreviewView {
    pub pending: String,
    pub repo: String,
    pub id: String,
    pub name: String,
    pub description: String,
    pub key: String,
    pub kinds: Vec<String>,
    pub listed: bool,
    pub devcontainer_notes: Vec<String>,
    pub approval: ApprovalView,
    pub notes: Vec<String>,
    pub progress: Vec<String>,
}

async fn preview_add(State(s): State<Arc<UiState>>, Json(req): Json<PreviewRequest>) -> ApiResult<PreviewView> {
    let cfg = s.config()?;
    let (api, arg, share) = (s.api.clone(), req.arg.clone(), req.share.max(1));
    let (p, progress) = tokio::task::spawn_blocking(move || {
        let mut progress = vec![];
        let p = projects::preview_add(&cfg, &arg, &api, None, share, &mut |m| progress.push(m.to_string()));
        (p, progress)
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let p = p?;
    let t = &p.fetched.devcontainer.toto;
    let view = PreviewView {
        pending: String::new(),
        repo: p.repo.clone(),
        id: t.id.clone(),
        name: t.name.clone(),
        description: t.description.clone(),
        key: t.public_key.clone(),
        kinds: t.kinds.clone(),
        listed: p.listed.is_some(),
        devcontainer_notes: p.fetched.devcontainer.notes.clone(),
        approval: approval_view(&p.approval),
        notes: p.notes.clone(),
        progress,
    };
    let pending = s.remember(Pending::Add { preview: Box::new(p), share });
    Ok(Json(PreviewView { pending, ..view }))
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckView {
    UpToDate { detail: String },
    Changed { pending: String, lines: Vec<String>, progress: Vec<String> },
}

async fn check(State(s): State<Arc<UiState>>, AxPath(id): AxPath<String>) -> ApiResult<CheckView> {
    let cfg = s.config()?;
    let (api, pid) = (s.api.clone(), id.clone());
    let (r, progress) = tokio::task::spawn_blocking(move || {
        let mut progress = vec![];
        let r = projects::preview_update(&cfg, &pid, &api, None, &mut |m| progress.push(m.to_string()));
        (r, progress)
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(match r? {
        UpdateCheck::UpToDate(detail) => CheckView::UpToDate { detail },
        UpdateCheck::Changed(c) => {
            let pending = s.remember(Pending::Update { id, approval: Box::new(c.preview.approval) });
            CheckView::Changed { pending, lines: c.lines, progress }
        }
    }))
}

#[derive(Serialize)]
pub struct Applied {
    pub message: String,
    pub notes: Vec<String>,
}

async fn approve(State(s): State<Arc<UiState>>, AxPath(pending): AxPath<String>) -> ApiResult<Applied> {
    let p = s.pending.lock().unwrap().remove(&pending).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "nothing pending under that id; preview again".into()))?;
    let mut cfg = s.config()?;
    let applied = match p {
        Pending::Add { preview, share } => {
            let notes = projects::apply_add(&mut cfg, &preview, &AddOptions { share, token_file: None })?;
            Applied { message: format!("added `{}`; restart the daemon to pick it up, and run `toto doctor`", preview.fetched.devcontainer.toto.id), notes }
        }
        Pending::Update { id, approval } => {
            projects::apply_update(&mut cfg, &id, *approval);
            Applied { message: format!("approved the new version of `{id}`; restart the daemon to pick it up"), notes: vec![] }
        }
    };
    cfg.save(&s.config_path)?;
    Ok(Json(applied))
}

async fn remove(State(s): State<Arc<UiState>>, AxPath(id): AxPath<String>) -> ApiResult<Applied> {
    let mut cfg = s.config()?;
    let message = projects::remove(&mut cfg, &id)?;
    cfg.save(&s.config_path)?;
    Ok(Json(Applied { message, notes: vec![] }))
}

#[derive(Serialize, Deserialize)]
pub struct PolicyView {
    pub daily_token_cap: u64,
    pub reserve_pct: u64,
    pub quiet_hours: Option<(u32, u32)>,
    pub project_shares: std::collections::BTreeMap<String, u32>,
}

async fn pause(State(s): State<Arc<UiState>>) -> ApiResult<crate::daemon::Status> {
    crate::control::pause(&s.state_dir)?;
    Ok(Json(status_now(&s)))
}

async fn resume(State(s): State<Arc<UiState>>) -> ApiResult<crate::daemon::Status> {
    crate::control::resume(&s.state_dir)?;
    Ok(Json(status_now(&s)))
}

/// The daemon's status file, with the pause marker applied: the file lags the marker by a few
/// seconds, and the page should not.
fn status_now(s: &UiState) -> crate::daemon::Status {
    let mut st = crate::daemon::Status::read(&s.state_dir).unwrap_or_default();
    let paused = crate::control::is_paused(&s.state_dir);
    if paused && !st.user_paused {
        st.user_paused = true;
        st.pause_reason = Some("paused by you".into());
        if st.state != "stopped" {
            st.state = "paused".into();
        }
    } else if !paused && st.user_paused {
        st.user_paused = false;
        st.pause_reason = None;
        st.state = "idle".into();
    }
    st
}

#[derive(Deserialize)]
struct EventsQuery {
    token: Option<String>,
}

/// Server-sent events: the status whenever it changes (and once on connect). `EventSource`
/// cannot set headers, so this endpoint alone takes the token as a query parameter.
async fn events(State(s): State<Arc<UiState>>, axum::extract::Query(q): axum::extract::Query<EventsQuery>) -> Response {
    if !q.token.as_deref().is_some_and(|t| constant_eq(t, &s.token)) {
        return ApiError(StatusCode::UNAUTHORIZED, "missing or wrong session token".into()).into_response();
    }
    use axum::response::sse::{Event, KeepAlive, Sse};
    let stream = futures_util::stream::unfold((s, String::new()), |(s, last)| async move {
        loop {
            let now = serde_json::to_string(&status_now(&s)).unwrap_or_default();
            if now != last {
                let ev = Ok::<Event, std::convert::Infallible>(Event::default().event("status").data(now.clone()));
                return Some((ev, (s, now)));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

async fn get_policy(State(s): State<Arc<UiState>>) -> ApiResult<PolicyView> {
    let p = s.config()?.policy;
    Ok(Json(PolicyView { daily_token_cap: p.daily_token_cap, reserve_pct: p.reserve_pct, quiet_hours: p.quiet_hours, project_shares: p.project_shares }))
}

async fn put_policy(State(s): State<Arc<UiState>>, Json(v): Json<PolicyView>) -> ApiResult<PolicyView> {
    if v.reserve_pct > 100 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "reserve_pct is a percentage".into()));
    }
    if let Some((a, b)) = v.quiet_hours
        && (a > 23 || b > 23)
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "quiet hours are 0-23".into()));
    }
    let mut cfg = s.config()?;
    if v.project_shares.keys().any(|id| !cfg.projects.contains_key(id)) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "shares may only name configured projects".into()));
    }
    cfg.policy.daily_token_cap = v.daily_token_cap;
    cfg.policy.reserve_pct = v.reserve_pct;
    cfg.policy.quiet_hours = v.quiet_hours;
    for (id, share) in &v.project_shares {
        cfg.policy.project_shares.insert(id.clone(), (*share).max(1));
    }
    cfg.save(&s.config_path)?;
    Ok(Json(v))
}

/// Every `/api` call must carry the session token.
async fn require_token(State(s): State<Arc<UiState>>, headers: HeaderMap, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let ok = headers.get(TOKEN_HEADER).and_then(|v| v.to_str().ok()).is_some_and(|t| constant_eq(t, &s.token));
    if ok { next.run(req).await } else { ApiError(StatusCode::UNAUTHORIZED, "missing or wrong session token: open the URL `toto ui` printed".into()).into_response() }
}

fn constant_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The embedded page: a file when it exists, else `index.html` (the app routes client-side).
async fn asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let candidates = [path.to_string(), format!("{}/index.html", path.trim_end_matches('/')), "index.html".to_string()];
    for c in candidates.iter().filter(|c| !c.is_empty() && !c.starts_with('/')) {
        if let Some(f) = Assets::get(c) {
            return ([(header::CONTENT_TYPE, mime_of(c))], f.data.into_owned()).into_response();
        }
    }
    (StatusCode::NOT_FOUND, "the UI is not built into this binary (build ui/ before `cargo build`)").into_response()
}

fn mime_of(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript",
        "css" => "text/css",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

pub fn router(state: Arc<UiState>) -> Router {
    let api = Router::new()
        .route("/overview", get(overview))
        .route("/projects", get(list_projects))
        .route("/projects/preview", post(preview_add))
        .route("/projects/{id}", get(project))
        .route("/projects/{id}/check", post(check))
        .route("/projects/{id}/remove", post(remove))
        .route("/pending/{id}/approve", post(approve))
        .route("/policy", get(get_policy).put(put_policy))
        .route("/pause", post(pause))
        .route("/resume", post(resume))
        .layer(axum::middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state.clone());
    let stream = Router::new().route("/api/events", get(events)).with_state(state);
    Router::new().nest("/api", api).merge(stream).fallback(get(asset))
}

/// Binds `addr` (loopback only) with the shared token from the state directory. Returns the
/// listener, the state and the URL to open.
pub async fn bind(config_path: PathBuf, state_dir: &std::path::Path, addr: &str) -> Result<(tokio::net::TcpListener, Arc<UiState>, String)> {
    let token = crate::control::load_or_create_token(state_dir)?;
    let state = Arc::new(UiState::new(config_path, token.clone())?);
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| Error::Sandbox(format!("cannot listen on {addr}: {e}")))?;
    let local = listener.local_addr()?;
    if !local.ip().is_loopback() {
        return Err(Error::Policy(format!("the local page serves loopback only, not {local}")));
    }
    Ok((listener, state, format!("http://{local}/?token={token}")))
}

/// `toto ui`: serves the page on `addr` until the process ends. When the daemon already serves
/// it there, prints that URL instead and returns.
pub async fn serve(config_path: PathBuf, addr: &str) -> Result<()> {
    let cfg = Config::load(&config_path)?;
    match bind(config_path, &cfg.state_dir, addr).await {
        Ok((listener, state, url)) => {
            println!("toto ui: {url}\n(close it with Ctrl-C)");
            axum::serve(listener, router(state)).await?;
            Ok(())
        }
        Err(e) if e.to_string().contains("in use") => {
            let token = crate::control::load_or_create_token(&cfg.state_dir)?;
            println!("already served (by the daemon): http://{addr}/?token={token}");
            Ok(())
        }
        Err(e) => Err(e),
    }
}
