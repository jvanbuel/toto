//! Writes a user-level service unit so the daemon starts at login and restarts on failure.

use crate::{Error, Result};
use std::path::{Path, PathBuf};

pub fn unit_path(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/LaunchAgents/be.togra.plist")
    } else {
        home.join(".config/systemd/user/togra.service")
    }
}

pub fn unit_contents(exe: &Path, config: &Path) -> String {
    if cfg!(target_os = "macos") {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>be.togra</string>
  <key>ProgramArguments</key><array><string>{}</string><string>run</string><string>--config</string><string>{}</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>Nice</key><integer>10</integer><key>LowPriorityIO</key><true/>
</dict></plist>
"#,
            exe.display(),
            config.display()
        )
    } else {
        format!(
            "[Unit]\nDescription=togra: donate spare AI capacity\nAfter=network-online.target\n\n[Service]\nExecStart={} run --config {}\nRestart=on-failure\nRestartSec=30\nNice=10\nNoNewPrivileges=true\n\n[Install]\nWantedBy=default.target\n",
            exe.display(),
            config.display()
        )
    }
}

/// Writes the unit and returns the command that enables it (we never run it for the user).
pub fn install(home: &Path, exe: &Path, config: &Path) -> Result<(PathBuf, &'static str)> {
    if !config.is_absolute() {
        return Err(Error::Policy("service config path must be absolute".into()));
    }
    let path = unit_path(home);
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, unit_contents(exe, config))?;
    let enable = if cfg!(target_os = "macos") { "launchctl load -w ~/Library/LaunchAgents/be.togra.plist" } else { "systemctl --user enable --now togra" };
    Ok((path, enable))
}
