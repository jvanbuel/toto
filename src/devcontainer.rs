//! A strict subset of the dev container spec (<https://containers.dev>): how a project names its
//! environment. Projects already have a `devcontainer.json` for their own developers; toto reads the
//! prebuilt `image` from it and nothing else that acts.
//!
//! Much of the spec acts on the machine that runs it (`initializeCommand` runs on the host, `mounts`
//! bind host paths, `runArgs` passes arbitrary docker flags, `privileged` and `capAdd` weaken the
//! sandbox). Other keys make the contributor's machine *build* the environment (`build`,
//! `dockerFile`, `features`): the steps run in a build container with network, which is contained but
//! is a stranger's code running before the contributor has approved anything, and the result is
//! not something that can be inspected and pinned like a published image. So all of these are
//! *refused* with a message instead of being silently dropped: the project builds its image in its
//! own CI and publishes it, and the contributor inspects and approves that image (`image`).
//! Keys that only matter in an editor or at dev time are ignored with a warning.

use crate::{Error, Result};

/// Keys that would act on the host or build on it: the file is refused.
const REFUSED: [(&str, &str); 13] = [
    ("build", "builds an image on the contributor's machine"),
    ("dockerFile", "builds an image on the contributor's machine"),
    ("dockerComposeFile", "starts other services on the contributor's machine"),
    ("service", "starts other services on the contributor's machine"),
    ("features", "runs install scripts on the contributor's machine"),
    ("mounts", "mounts host paths into the container"),
    ("workspaceMount", "mounts host paths into the container"),
    ("runArgs", "passes arbitrary flags to docker"),
    ("privileged", "removes the container's isolation"),
    ("capAdd", "adds capabilities to the container"),
    ("securityOpt", "changes the container's security settings"),
    ("initializeCommand", "runs a command on the contributor's machine"),
    ("init", "changes how the container starts"),
];

/// Keys read or harmless: no warning.
const QUIET: [&str; 4] = ["$schema", "name", "image", "customizations"];

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub image: String,
    /// What was ignored and why, for the project and the contributor to see.
    pub warnings: Vec<String>,
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

pub fn parse(text: &str) -> Result<Parsed> {
    let bad = |m: String| Error::Policy(format!("devcontainer.json: {m}"));
    if text.len() > 256 * 1024 {
        return Err(bad("too large".into()));
    }
    let v: serde_json::Value = serde_json::from_str(&strip_jsonc(text)).map_err(|e| bad(e.to_string()))?;
    let obj = v.as_object().ok_or_else(|| bad("not an object".into()))?;
    let refused: Vec<String> = REFUSED.iter().filter(|(k, _)| obj.contains_key(*k)).map(|(k, why)| format!("`{k}` {why}")).collect();
    if !refused.is_empty() {
        return Err(bad(format!(
            "{}. toto runs a published image only: build it in your CI (for example with the dev container CLI), push it, and name it in `image`",
            refused.join("; ")
        )));
    }
    let image = obj.get("image").and_then(|i| i.as_str()).ok_or_else(|| bad("no `image`: name a published image (registry/path:tag)".into()))?;
    if !valid_image_ref(image) {
        return Err(bad(format!("image `{image}` must be fully qualified with a registry and a tag or digest, e.g. ghcr.io/acme/env:1.2")));
    }
    let warnings = obj
        .keys()
        .filter(|k| !QUIET.contains(&k.as_str()))
        .map(|k| match k.as_str() {
            "containerEnv" | "remoteEnv" => format!("`{k}` is ignored: bake variables into the image with ENV"),
            "onCreateCommand" | "updateContentCommand" | "postCreateCommand" | "postStartCommand" | "postAttachCommand" => format!("`{k}` is ignored: toto does not run setup commands; put the setup in the image"),
            "remoteUser" | "containerUser" | "updateRemoteUserUID" => format!("`{k}` is ignored: tasks always run as an unprivileged user"),
            other => format!("`{other}` is ignored"),
        })
        .collect();
    Ok(Parsed { image: image.to_string(), warnings })
}
