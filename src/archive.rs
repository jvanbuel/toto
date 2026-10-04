//! Task inputs and outputs as standard tar archives, parsed safely on the host.
//!
//! Inputs are strict: only regular files and directories, safe relative paths, bounded sizes.
//! Outputs are changed files plus deletions, using the OCI image-layer convention for removals
//! (whiteout entries named `.wh.<name>`). Nothing here ever extracts a tar with a general-purpose
//! tool: entries are validated and written one by one, so a hostile archive cannot escape its
//! root.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
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

/// Builds a standard tar: files as regular entries, deletions as OCI-layer whiteouts
/// (`dir/.wh.<name>`, an empty file), the convention image layers use for "removed".
pub fn to_bytes(records: &[Record]) -> Result<Vec<u8>> {
    let mut b = tar::Builder::new(Vec::new());
    for r in records {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mtime(0);
        h.set_uid(0);
        h.set_gid(0);
        match r {
            Record::File { path, mode, data } => {
                h.set_size(data.len() as u64);
                h.set_mode(*mode);
                b.append_data(&mut h, path, &data[..]).map_err(|e| format!("{path}: {e}"))?;
            }
            Record::Deleted { path } => {
                h.set_size(0);
                h.set_mode(0o644);
                let (dir, name) = path.rsplit_once('/').map_or(("", path.as_str()), |(d, n)| (d, n));
                let wh = if dir.is_empty() { format!(".wh.{name}") } else { format!("{dir}/.wh.{name}") };
                b.append_data(&mut h, wh, std::io::empty()).map_err(|e| format!("{path}: {e}"))?;
            }
        }
    }
    b.into_inner().map_err(|e| e.to_string())
}

pub fn write_records<W: Write>(w: &mut W, records: &[Record]) -> Result<()> {
    w.write_all(&to_bytes(records)?).map_err(|e| e.to_string())
}

/// What to do with entries that are not regular files or directories.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Reject symlinks, hardlinks, devices and so on (task inputs).
    Strict,
    /// Skip them (a dump of a workspace the agent has been writing to).
    Lenient,
}

/// One interpreted tar entry.
enum Item {
    File { path: String, mode: u32, size: u64 },
    Deleted(String),
    Skip,
}

fn mode_bits(m: u32) -> u32 {
    if m & 0o111 != 0 { 0o755 } else { 0o644 }
}

/// Maps a tar entry header to a safe, normalised item (no data is read here).
fn classify<R: Read>(e: &tar::Entry<'_, R>, mode: Mode) -> Result<Item> {
    use tar::EntryType as T;
    let ty = e.header().entry_type();
    let raw = e.path().map_err(|e| format!("bad entry path: {e}"))?;
    let raw = raw.to_str().ok_or("entry path is not valid UTF-8")?.to_string();
    let path = raw.trim_start_matches("./").trim_end_matches('/').to_string();
    match ty {
        T::Directory => return Ok(Item::Skip),
        T::Regular | T::Continuous => {}
        _ if mode == Mode::Lenient => return Ok(Item::Skip),
        other => return Err(format!("unsupported entry type {other:?} for `{raw}`")),
    }
    if path.is_empty() || path == "." {
        return Ok(Item::Skip);
    }
    let size = e.header().size().map_err(|e| e.to_string())?;
    let (dir, name) = path.rsplit_once('/').map_or(("", path.as_str()), |(d, n)| (d, n));
    if let Some(target) = name.strip_prefix(".wh.") {
        if target == ".wh..opq" || target.is_empty() || size != 0 {
            return Err(format!("unsupported whiteout `{raw}`"));
        }
        let deleted = if dir.is_empty() { target.to_string() } else { format!("{dir}/{target}") };
        return if valid_path(&deleted) { Ok(Item::Deleted(deleted)) } else { Err(format!("unsafe path `{raw}`")) };
    }
    if !valid_path(&path) {
        return Err(format!("unsafe path `{raw}`"));
    }
    Ok(Item::File { path, mode: mode_bits(e.header().mode().unwrap_or(0o644)), size })
}

/// Reads and validates a whole tar; entry sizes are checked before any allocation.
pub fn read_records<R: Read>(r: R, limits: Limits, mode: Mode) -> Result<Vec<Record>> {
    let (mut out, mut total) = (Vec::new(), 0u64);
    let mut ar = tar::Archive::new(r);
    for entry in ar.entries().map_err(|e| format!("not a tar archive: {e}"))? {
        let mut e = entry.map_err(|e| format!("bad tar entry: {e}"))?;
        match classify(&e, mode)? {
            Item::Skip => {}
            Item::Deleted(path) => out.push(Record::Deleted { path }),
            Item::File { path, mode, size } => {
                total = total.saturating_add(size);
                if total > limits.max_total_bytes || out.len() >= limits.max_files {
                    return Err(format!("archive exceeds limits ({} bytes / {} files)", limits.max_total_bytes, limits.max_files));
                }
                let mut data = vec![0u8; size as usize];
                e.read_exact(&mut data).map_err(|_| "truncated file data".to_string())?;
                out.push(Record::File { path, mode, data });
            }
        }
    }
    Ok(out)
}

/// Strict parse of inputs (hostile entry types are errors).
pub fn from_bytes(bytes: &[u8], limits: Limits) -> Result<Vec<Record>> {
    read_records(bytes, limits, Mode::Strict)
}

/// Compares a (streamed) workspace tar against `base` without keeping unchanged files in memory:
/// each file is hashed as it streams past and only changed files up to `limits` are retained.
pub fn changes_from_tar<R: Read>(r: R, base: &BTreeMap<String, String>, limits: Limits) -> Result<Vec<Record>> {
    let (mut out, mut total) = (Vec::new(), 0u64);
    let mut seen = std::collections::BTreeSet::new();
    let mut ar = tar::Archive::new(r);
    for entry in ar.entries().map_err(|e| format!("not a tar archive: {e}"))? {
        let mut e = entry.map_err(|e| format!("bad tar entry: {e}"))?;
        let Item::File { path, mode, size } = classify(&e, Mode::Lenient)? else { continue };
        if seen.len() >= 500_000 {
            return Err("workspace has too many files".into());
        }
        let keep = size <= limits.max_total_bytes;
        let (mut hasher, mut data, mut buf) = (Sha256::new(), Vec::new(), [0u8; 64 * 1024]);
        loop {
            let n = e.read(&mut buf).map_err(|e| format!("{path}: {e}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            if keep {
                data.extend_from_slice(&buf[..n]);
            }
        }
        seen.insert(path.clone());
        if base.get(&path).is_some_and(|h| *h == hex::encode(hasher.finalize())) {
            continue;
        }
        if !keep {
            return Err(format!("changed file `{path}` is larger than the artifact limit ({} bytes)", limits.max_total_bytes));
        }
        total = total.saturating_add(size);
        if total > limits.max_total_bytes || out.len() >= limits.max_files {
            return Err(format!("changes exceed the artifact limit ({} bytes)", limits.max_total_bytes));
        }
        out.push(Record::File { path, mode, data });
    }
    out.extend(base.keys().filter(|p| !seen.contains(*p)).map(|p| Record::Deleted { path: p.clone() }));
    Ok(out)
}

/// Content hashes of parsed input records: the baseline `changes_from_tar` compares against.
pub fn baseline_of(records: &[Record]) -> BTreeMap<String, String> {
    records.iter().filter_map(|r| if let Record::File { path, data, .. } = r { Some((path.clone(), sha256_hex(data))) } else { None }).collect()
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
