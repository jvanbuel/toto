#![allow(dead_code)] // shared with the static bridge binary, which uses only part of it
//! The togra archive: a minimal, safe container for task inputs and outputs.
//!
//! Only regular files and deletions can be expressed: no symlinks, hardlinks, devices or
//! absolute paths, so unpacking cannot escape its root. Used by the library (host side) and,
//! via `#[path]`, by the static `togra-mcp-exec` bridge inside containers, so it depends on
//! `std`, `serde_json`, `sha2` and `hex` only.
//!
//! Wire format: for each record a JSON header line, then (for files) exactly `size` raw bytes.
//! `{"t":"file","path":"a/b.txt","mode":420,"size":12}\n<12 bytes>`, `{"t":"del","path":"x"}\n`,
//! and a final `{"t":"end"}\n`.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    File { path: String, mode: u32, data: Vec<u8> },
    Deleted { path: String },
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_total_bytes: u64,
    pub max_files: usize,
}

impl Limits {
    pub const fn new(max_total_bytes: u64) -> Self {
        Self { max_total_bytes, max_files: 20_000 }
    }
}

pub type Result<T> = std::result::Result<T, String>;

/// A path that stays inside its root: relative, no `.`/`..`, no empty or control components.
pub fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 512
        && p.split('/').count() <= 32
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != ".." && !c.chars().any(|ch| ch.is_control() || ch == '\\'))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn write_records<W: Write>(w: &mut W, records: &[Record]) -> Result<()> {
    let io = |e: std::io::Error| e.to_string();
    for r in records {
        match r {
            Record::File { path, mode, data } => {
                writeln!(w, "{}", json!({"t": "file", "path": path, "mode": mode, "size": data.len()})).map_err(io)?;
                w.write_all(data).map_err(io)?;
            }
            Record::Deleted { path } => writeln!(w, "{}", json!({"t": "del", "path": path})).map_err(io)?,
        }
    }
    writeln!(w, "{}", json!({"t": "end"})).map_err(io)
}

pub fn to_bytes(records: &[Record]) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    write_records(&mut v, records)?;
    Ok(v)
}

/// Reads and validates a whole archive; sizes are checked before any allocation.
pub fn read_records<R: BufRead>(r: &mut R, limits: Limits) -> Result<Vec<Record>> {
    let (mut out, mut total) = (Vec::new(), 0u64);
    loop {
        let mut line = String::new();
        let n = r.by_ref().take(4096).read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 || !line.ends_with('\n') {
            return Err("truncated archive (no end marker)".into());
        }
        let h: Value = serde_json::from_str(line.trim_end()).map_err(|e| format!("bad header: {e}"))?;
        let path = h["path"].as_str().unwrap_or("").to_string();
        match h["t"].as_str() {
            Some("end") => return Ok(out),
            Some("file") => {
                let size = h["size"].as_u64().ok_or("file without size")?;
                if !valid_path(&path) {
                    return Err(format!("unsafe path `{path}`"));
                }
                total = total.saturating_add(size);
                if total > limits.max_total_bytes || out.len() >= limits.max_files {
                    return Err(format!("archive exceeds limits ({} bytes / {} files)", limits.max_total_bytes, limits.max_files));
                }
                let mut data = vec![0u8; size as usize];
                r.read_exact(&mut data).map_err(|_| "truncated file data".to_string())?;
                let mode = if h["mode"].as_u64().unwrap_or(0o644) & 0o111 != 0 { 0o755 } else { 0o644 };
                out.push(Record::File { path, mode, data });
            }
            Some("del") => {
                if !valid_path(&path) {
                    return Err(format!("unsafe path `{path}`"));
                }
                out.push(Record::Deleted { path });
            }
            other => return Err(format!("unknown record type {other:?}")),
        }
    }
}

pub fn from_bytes(bytes: &[u8], limits: Limits) -> Result<Vec<Record>> {
    read_records(&mut std::io::BufReader::new(bytes), limits)
}

/// Regular files under `root` (symlinks and special files are ignored), keyed by relative path.
fn walk(root: &Path, max_files: usize) -> Result<BTreeMap<String, PathBuf>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let e = e.map_err(|e| e.to_string())?;
            let ft = e.file_type().map_err(|e| e.to_string())?;
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                let rel = e.path().strip_prefix(root).map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
                if valid_path(&rel) {
                    out.insert(rel, e.path());
                }
                if out.len() > max_files {
                    return Err(format!("more than {max_files} files"));
                }
            }
        }
    }
    Ok(out)
}

fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::metadata(p).map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false) { 0o755 } else { 0o644 }
}

/// Packs every regular file under `root`.
pub fn pack_dir(root: &Path, limits: Limits) -> Result<Vec<Record>> {
    let (mut out, mut total) = (Vec::new(), 0u64);
    for (path, full) in walk(root, limits.max_files)? {
        let data = std::fs::read(&full).map_err(|e| format!("{path}: {e}"))?;
        total = total.saturating_add(data.len() as u64);
        if total > limits.max_total_bytes {
            return Err(format!("more than {} bytes", limits.max_total_bytes));
        }
        out.push(Record::File { mode: mode_of(&full), path, data });
    }
    Ok(out)
}

/// Writes records under `root` (which should be empty or fresh). Refuses to follow or replace
/// anything that already exists as a symlink, and re-checks that every target stays under `root`.
pub fn unpack_to(root: &Path, records: &[Record]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let canon = root.canonicalize().map_err(|e| e.to_string())?;
    for r in records {
        match r {
            Record::File { path, mode, data } => {
                if !valid_path(path) {
                    return Err(format!("unsafe path `{path}`"));
                }
                let target = canon.join(path);
                let parent = target.parent().ok_or("no parent")?;
                std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
                if !parent.canonicalize().map_err(|e| e.to_string())?.starts_with(&canon) {
                    return Err(format!("`{path}` escapes the workspace"));
                }
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(*mode).open(&target).map_err(|e| format!("{path}: {e}"))?;
                f.write_all(data).map_err(|e| e.to_string())?;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(*mode)).map_err(|e| e.to_string())?;
            }
            Record::Deleted { path } => {
                if !valid_path(path) {
                    return Err(format!("unsafe path `{path}`"));
                }
                let _ = std::fs::remove_file(canon.join(path));
            }
        }
    }
    Ok(())
}

/// Content hash of every regular file under `root`, the baseline for `changes_since`.
pub fn baseline(root: &Path, max_files: usize) -> Result<BTreeMap<String, String>> {
    walk(root, max_files)?.into_iter().map(|(p, full)| Ok((p, sha256_hex(&std::fs::read(&full).map_err(|e| e.to_string())?)))).collect()
}

/// Files added or modified since `base`, and files deleted, subject to `limits`.
pub fn changes_since(root: &Path, base: &BTreeMap<String, String>, limits: Limits) -> Result<Vec<Record>> {
    let (mut out, mut total) = (Vec::new(), 0u64);
    let current = walk(root, limits.max_files.max(base.len()))?;
    for (path, full) in &current {
        let data = std::fs::read(full).map_err(|e| format!("{path}: {e}"))?;
        if base.get(path).is_some_and(|h| *h == sha256_hex(&data)) {
            continue;
        }
        total = total.saturating_add(data.len() as u64);
        if total > limits.max_total_bytes || out.len() >= limits.max_files {
            return Err(format!("changes exceed the artifact limit ({} bytes)", limits.max_total_bytes));
        }
        out.push(Record::File { path: path.clone(), mode: mode_of(full), data });
    }
    out.extend(base.keys().filter(|p| !current.contains_key(*p)).map(|p| Record::Deleted { path: p.clone() }));
    Ok(out)
}
