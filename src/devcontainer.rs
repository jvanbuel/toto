//! The project's `.devcontainer/devcontainer.json` (<https://containers.dev>): the same file its
//! developers use, with toto's bits under `customizations.toto`, the extension point the spec
//! reserves for tools.
//!
//! toto never runs `devcontainer up` on a stranger's file. It reads two things: the published
//! image (`customizations.toto.image`, or the top-level `image`), and `customizations.toto` (id,
//! key, kinds, agent directory). Keys that act on the host (`runArgs`, `mounts`, `privileged`,
//! ...) are simply not applied, because toto only ever starts the image under its own flags. When
//! the file builds its image (`build`, `dockerFile`, `features`) and names no published one, the
//! contributor's machine can prebuild it (`prebuild`): the spec's own prebuild phase, build +
//! `onCreateCommand` + `updateContentCommand`, snapshotted. `postCreateCommand` and later never
//! run: tasks start offline from the snapshot, as Codespaces prebuilds define it.

use crate::{Error, Result};
use serde::Deserialize;

pub const PATH: &str = ".devcontainer/devcontainer.json";
pub const ALT_PATH: &str = ".devcontainer.json";

/// `customizations.toto`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Toto {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Hex Ed25519 public key tasks are signed with.
    pub public_key: String,
    pub kinds: Vec<String>,
    /// The published image tasks run in, when the file itself builds (`build`/`features`).
    #[serde(default)]
    pub image: Option<String>,
    /// Omnigent agent directory in the repository; default `.toto/agent`.
    #[serde(default)]
    pub agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Devcontainer {
    pub toto: Toto,
    /// The published image to run, if any.
    pub image: Option<String>,
    /// The file builds its own image (`build`, `dockerFile` or `features`).
    pub builds: bool,
    /// What a prebuild would run, and what is ignored; shown to the contributor.
    pub notes: Vec<String>,
}

/// Removes `//` and `/* */` comments and trailing commas (dev container files are JSONC).
pub fn strip_jsonc(text: &str) -> String {
    let (c, mut out, mut i, mut in_str) = (text.chars().collect::<Vec<_>>(), String::new(), 0, false);
    while i < c.len() {
        let ch = c[i];
        if in_str {
            out.push(ch);
            if ch == '\\' && i + 1 < c.len() {
                out.push(c[i + 1]);
                i += 1;
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
            out.push(ch);
        } else if ch == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        } else if ch == '/' && c.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        } else if ch == ',' && c[i + 1..].iter().find(|x| !x.is_whitespace()).is_some_and(|x| matches!(x, '}' | ']')) {
            // trailing comma: drop it
        } else {
            out.push(ch);
        }
        i += 1;
    }
    out
}

/// A fully qualified image reference: a registry host, a path, and a tag or digest.
pub fn valid_image_ref(r: &str) -> bool {
    let name_ok = |s: &str| s.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')));
    let (name, tagged) = match (r.split_once('@'), r.rsplit_once(':')) {
        (Some((n, d)), _) => (n, d.starts_with("sha256:") && d.len() == 71 && d[7..].bytes().all(|b| b.is_ascii_hexdigit())),
        (None, Some((n, t))) if !t.contains('/') => (n, !t.is_empty() && t.len() <= 128 && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))),
        _ => (r, false),
    };
    let Some((host, path)) = name.split_once('/') else { return false };
    let host_name = host.rsplit_once(':').map_or(host, |h| h.0); // allow registry:port
    r.len() <= 256 && tagged && name_ok(path) && !host_name.is_empty() && (host.contains('.') || host.contains(':') || host == "localhost") && host_name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

/// A project id: 1-64 characters of `a-z`, `0-9`, `-` or `_`.
pub fn valid_id(s: &str) -> bool {
    ident(s)
}

fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Keys that `devcontainer up` would apply to the host; a prebuild drops them from the override
/// config it hands the CLI, and tasks never see them.
pub const HOST_KEYS: [&str; 9] = ["runArgs", "mounts", "workspaceMount", "privileged", "capAdd", "securityOpt", "initializeCommand", "dockerComposeFile", "service"];

pub fn parse(text: &str) -> Result<Devcontainer> {
    let bad = |m: String| Error::Policy(format!("devcontainer.json: {m}"));
    if text.len() > 256 * 1024 {
        return Err(bad("too large".into()));
    }
    let v: serde_json::Value = serde_json::from_str(&strip_jsonc(text)).map_err(|e| bad(e.to_string()))?;
    let obj = v.as_object().ok_or_else(|| bad("not an object".into()))?;
    let toto: Toto = serde_json::from_value(obj.get("customizations").and_then(|c| c.get("toto")).cloned().ok_or_else(|| bad("no customizations.toto (is this a toto project?)".into()))?).map_err(|e| bad(format!("customizations.toto: {e}")))?;
    if !ident(&toto.id) {
        return Err(bad(format!("customizations.toto.id `{}` must be 1-64 characters of a-z, 0-9, - or _", toto.id)));
    }
    if hex::decode(&toto.public_key).ok().filter(|b| b.len() == 32).is_none() {
        return Err(bad("customizations.toto.public_key must be 32 bytes of hex".into()));
    }
    if toto.kinds.is_empty() || toto.kinds.iter().any(|k| !ident(k)) {
        return Err(bad("customizations.toto.kinds must be a non-empty list of simple names".into()));
    }
    if let Some(a) = &toto.agent
        && !crate::archive::valid_path(a)
    {
        return Err(bad(format!("customizations.toto.agent `{a}` must be a relative path")));
    }
    let builds = ["build", "dockerFile", "features"].iter().any(|k| obj.contains_key(*k));
    let image = match (toto.image.as_deref(), obj.get("image").and_then(|i| i.as_str())) {
        (Some(i), _) | (None, Some(i)) => {
            if !valid_image_ref(i) {
                return Err(bad(format!("image `{i}` must be fully qualified with a registry and a tag or digest, e.g. ghcr.io/acme/env:1.2")));
            }
            Some(i.to_string())
        }
        (None, None) => None,
    };
    if image.is_none() && !builds {
        return Err(bad("names no image and builds none: set `image`, or `build`/`features` (then a contributor prebuilds it), or customizations.toto.image".into()));
    }
    let mut notes = vec![];
    if image.is_some() && builds {
        notes.push(format!("the file builds its own image for developers; tasks run the published one ({})", image.as_deref().unwrap_or("")));
    } else if builds {
        notes.push("no published image: your machine prebuilds it (build, onCreateCommand, updateContentCommand), then tasks run the snapshot offline".into());
    }
    for k in ["onCreateCommand", "updateContentCommand"] {
        if obj.contains_key(k) {
            notes.push(format!("`{k}` runs at prebuild{}", if image.is_some() { " only if your machine builds; the published image is used as is" } else { "" }));
        }
    }
    for k in ["postCreateCommand", "postStartCommand", "postAttachCommand"] {
        if obj.contains_key(k) {
            notes.push(format!("`{k}` never runs: tasks start offline from the snapshot (as Codespaces prebuilds define it)"));
        }
    }
    let dropped: Vec<&str> = HOST_KEYS.iter().copied().filter(|k| obj.contains_key(*k)).collect();
    if !dropped.is_empty() {
        notes.push(format!("not applied (toto starts the image under its own flags): {}", dropped.join(", ")));
    }
    for k in ["containerEnv", "remoteEnv"] {
        if obj.contains_key(k) {
            notes.push(format!("`{k}` is not applied: bake variables into the image with ENV"));
        }
    }
    if obj.get("remoteUser").is_some() || obj.get("containerUser").is_some() {
        notes.push("`remoteUser`/`containerUser` are not applied: tasks always run as an unprivileged user".into());
    }
    Ok(Devcontainer { toto, image, builds, notes })
}
