//! Contributor control of the daemon that works across processes: a pause marker the daemon
//! loop honours, and the local API's session token, both in the state directory.
//!
//! The daemon, `toto pause`, `toto resume` and the local page are separate processes; a file
//! is the simplest thing they can all see. The daemon checks the marker before every task
//! and while it waits, so a pause takes effect within seconds and never interrupts a task
//! that is already running (the lease would be lost and the project's work wasted).

use crate::Result;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn pause_marker(state_dir: &Path) -> PathBuf {
    state_dir.join("paused")
}

/// Whether the contributor has paused the runner.
pub fn is_paused(state_dir: &Path) -> bool {
    pause_marker(state_dir).exists()
}

/// Pauses: no new task is taken until `resume`. A running task finishes first.
pub fn pause(state_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(pause_marker(state_dir), chrono::Local::now().to_rfc3339())?;
    Ok(())
}

pub fn resume(state_dir: &Path) -> Result<()> {
    match std::fs::remove_file(pause_marker(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn token_path(state_dir: &Path) -> PathBuf {
    state_dir.join("ui.token")
}

/// The local API's session token: created once (mode 600) and shared by the daemon, `toto ui`
/// and anything else running as this user, so the page keeps working across restarts and a
/// native app can find it. Other users on the machine cannot read it.
pub fn load_or_create_token(state_dir: &Path) -> Result<String> {
    let path = token_path(state_dir);
    if let Ok(t) = std::fs::read_to_string(&path)
        && t.trim().len() == 64
    {
        return Ok(t.trim().to_string());
    }
    std::fs::create_dir_all(state_dir)?;
    let token = hex::encode(crate::manifest::generate_key().to_bytes());
    std::fs::write(&path, &token)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(token)
}
