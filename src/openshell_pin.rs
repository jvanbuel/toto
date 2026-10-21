//! The OpenShell release toto ships with (`openshell.lock.toml`, ADR 17): which version, which
//! archive per platform with its SHA-256, and which supervisor and sandbox-runtime images by
//! digest. toto installs and runs nothing that does not match it.
//!
//! Binaries are found, in order: in `bin_dir` from the config (development, air-gapped hosts);
//! next to the toto executable (the release archive ships them together); in toto's state
//! directory, where `toto openshell install` puts them.

use crate::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const LOCK: &str = include_str!("../openshell.lock.toml");

/// The binaries toto runs. The VM driver is optional (`compute_driver = "vm"`).
pub const BINARIES: [&str; 3] = ["openshell", "openshell-gateway", "openshell-driver-vm"];

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Asset {
    pub asset: String,
    pub sha256: String,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize, PartialEq, Eq)]
pub struct Images {
    pub supervisor: String,
    pub sandbox_runtime: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Lock {
    pub version: String,
    pub release_url: String,
    pub images: Images,
    /// Per platform (`x86_64-linux`, `aarch64-macos`, ...), per binary name.
    pub binaries: BTreeMap<String, BTreeMap<String, Asset>>,
}

impl Lock {
    pub fn embedded() -> Self {
        Self::parse(LOCK).expect("openshell.lock.toml is valid (checked by tests)")
    }

    pub fn parse(text: &str) -> Result<Self> {
        let l: Lock = toml::from_str(text).map_err(|e| Error::Sandbox(format!("openshell.lock.toml: {e}")))?;
        for (name, img) in [("supervisor", &l.images.supervisor), ("sandbox_runtime", &l.images.sandbox_runtime)] {
            if !img.split_once("@sha256:").is_some_and(|(_, d)| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(Error::Sandbox(format!("openshell.lock.toml: the {name} image must be pinned by digest")));
            }
        }
        Ok(l)
    }

    /// This machine's platform key.
    pub fn platform() -> String {
        format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    }

    pub fn assets(&self, platform: &str) -> Result<&BTreeMap<String, Asset>> {
        self.binaries.get(platform).ok_or_else(|| Error::Sandbox(format!("OpenShell {} has no build for {platform} (supported: {})", self.version, self.binaries.keys().cloned().collect::<Vec<_>>().join(", "))))
    }

    /// Whether every archive of `platform` has a pinned checksum.
    pub fn pinned(&self, platform: &str) -> bool {
        self.assets(platform).is_ok_and(|a| a.values().all(|x| x.sha256.len() == 64))
    }

    /// Where `toto openshell install` puts this version's binaries.
    pub fn install_dir(&self, state_dir: &Path) -> PathBuf {
        state_dir.join("openshell").join(&self.version).join("bin")
    }
}

/// Where the binaries were found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bins {
    pub dir: PathBuf,
    pub cli: PathBuf,
    pub gateway: PathBuf,
}

fn bins_in(dir: &Path) -> Option<Bins> {
    let (cli, gateway) = (dir.join("openshell"), dir.join("openshell-gateway"));
    (cli.is_file() && gateway.is_file()).then(|| Bins { dir: dir.to_path_buf(), cli, gateway })
}

/// Finds the OpenShell binaries (see the module docs for the order).
pub fn find(lock: &Lock, bin_dir: Option<&Path>, state_dir: &Path) -> Result<Bins> {
    if let Some(d) = bin_dir {
        return bins_in(d).ok_or_else(|| Error::Sandbox(format!("no `openshell` and `openshell-gateway` in {}", d.display())));
    }
    // Through any symlink: install.sh links `toto` onto the PATH from the release's directory.
    let beside = std::env::current_exe().and_then(std::fs::canonicalize).ok().and_then(|e| e.parent().map(Path::to_path_buf));
    for d in beside.into_iter().chain([lock.install_dir(state_dir)]) {
        if let Some(b) = bins_in(&d) {
            return Ok(b);
        }
    }
    Err(Error::Sandbox(format!("OpenShell {} is not installed: run `toto openshell install` (or install the toto release archive, which ships it)", lock.version)))
}

/// Downloads this platform's archives from the release, checks each against the lock, and puts
/// the binaries in `dest`. `with_vm` also installs the VM driver.
pub fn install(lock: &Lock, platform: &str, dest: &Path, with_vm: bool) -> Result<Vec<PathBuf>> {
    let assets = lock.assets(platform)?;
    if !lock.pinned(platform) {
        return Err(Error::Sandbox(format!(
            "this toto build pins OpenShell {} without checksums for {platform}; refusing to install unverified binaries (maintainers: scripts/pin-openshell.sh)",
            lock.version
        )));
    }
    std::fs::create_dir_all(dest)?;
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(600))).build().into();
    let mut out = vec![];
    for (name, a) in assets {
        if name == "openshell-driver-vm" && !with_vm {
            continue;
        }
        let url = format!("{}/{}", lock.release_url.trim_end_matches('/'), a.asset);
        let mut resp = agent.get(&url).call().map_err(|e| Error::Sandbox(format!("{url}: {e}")))?;
        let bytes = resp.body_mut().with_config().limit(512 << 20).read_to_vec().map_err(|e| Error::Sandbox(format!("{url}: {e}")))?;
        out.push(unpack_verified(&bytes, a, name, dest)?);
    }
    Ok(out)
}

/// Checks `archive` against the pinned checksum and writes its single binary `name` to `dest`.
pub fn unpack_verified(archive: &[u8], a: &Asset, name: &str, dest: &Path) -> Result<PathBuf> {
    let got = crate::archive::sha256_hex(archive);
    if !got.eq_ignore_ascii_case(&a.sha256) {
        return Err(Error::Sandbox(format!("{}: checksum {got} does not match the pinned {}", a.asset, a.sha256)));
    }
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries().map_err(|e| Error::Sandbox(format!("{}: {e}", a.asset)))? {
        let mut e = entry.map_err(|e| Error::Sandbox(format!("{}: {e}", a.asset)))?;
        let path = e.path().map_err(|e| Error::Sandbox(e.to_string()))?.to_path_buf();
        if path.file_name().and_then(|f| f.to_str()) != Some(name) || !e.header().entry_type().is_file() {
            continue;
        }
        let mut data = vec![];
        e.read_to_end(&mut data)?;
        let target = dest.join(name);
        let tmp = dest.join(format!(".{name}.partial"));
        std::fs::write(&tmp, &data)?;
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        std::fs::rename(&tmp, &target)?;
        return Ok(target);
    }
    Err(Error::Sandbox(format!("{} holds no `{name}`", a.asset)))
}
