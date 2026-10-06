//! Credential files: read with a permissions check, written with mode 0600.

use crate::{Error, Result};
use std::path::Path;

/// Reads a token or key file. Refuses an empty file and warns about loose permissions.
pub fn read_secret(path: &Path) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| Error::Policy(format!("{}: {e}", path.display())))?;
    if meta.permissions().mode() & 0o077 != 0 {
        eprintln!("warning: {} is readable by others (chmod 600)", path.display());
    }
    let s = std::fs::read_to_string(path)?;
    let s = s.trim().to_string();
    if s.is_empty() {
        return Err(Error::Policy(format!("{} is empty", path.display())));
    }
    Ok(s)
}

/// Writes a secret with mode 0600, creating the parent directory.
pub fn save_token(path: &Path, token: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(path, token.trim())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
