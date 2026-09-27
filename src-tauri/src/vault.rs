//! Secrets at rest: one encrypted file, one Credential Manager item.
//!
//! `secrets.bin` in WattWall's data folder is a 12-byte nonce followed by the
//! AES-256-GCM ciphertext of a small JSON payload, written to a temp file and
//! renamed. The 32-byte sealing key is the only item WattWall keeps in
//! Windows Credential Manager (`WattWall/vault-key`); it is read at most once
//! per process, and only once a vault file exists or a secret is saved.
//! The debug build's test mode seals with a fixed key and never touches
//! Credential Manager.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use zeroize::Zeroize;

const TARGET: &str = "WattWall/vault-key";
const FILE: &str = "secrets.bin";
/// AES-GCM's tag; anything shorter than nonce + tag cannot be a vault.
const TAG_LEN: usize = 16;
/// Test mode's key. Only reachable in a debug build with WATTWALL_FAKE=1.
const TEST_KEY: [u8; 32] = [0x5A; 32];

/// The key once read or created; a failed read is not cached.
static KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// What the vault holds.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virustotal_key: Option<String>,
}

impl Drop for Secrets {
    fn drop(&mut self) {
        if let Some(key) = self.virustotal_key.as_mut() {
            key.zeroize();
        }
    }
}

enum KeySource {
    CredentialManager,
    Fixed([u8; 32]),
}

pub struct Vault {
    path: PathBuf,
    key: KeySource,
}

impl Vault {
    /// The vault in `data_dir`, sealed by the Credential Manager key, or by
    /// the fixed test key when `test_copy` is set.
    pub fn new(data_dir: &Path, test_copy: bool) -> Self {
        Self {
            path: data_dir.join(FILE),
            key: if test_copy {
                KeySource::Fixed(TEST_KEY)
            } else {
                KeySource::CredentialManager
            },
        }
    }

    #[cfg(test)]
    fn with_key(path: PathBuf, key: [u8; 32]) -> Self {
        Self {
            path,
            key: KeySource::Fixed(key),
        }
    }

    /// Whether a vault file exists. Costs no Credential Manager read.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// The secrets, or `None` when there is no vault file.
    pub fn load(&self) -> Result<Option<Secrets>, String> {
        let mut bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(format!("Could not read WattWall's secrets: {err}")),
        };
        if bytes.len() < NONCE_LEN + TAG_LEN {
            return Err(unreadable());
        }
        let key = self.sealing_key(false)?;
        let (nonce, sealed) = bytes.split_at_mut(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| unreadable())?;
        let plain = key
            .open_in_place(nonce, Aad::empty(), sealed)
            .map_err(|_| unreadable())?;
        let secrets = serde_json::from_slice(plain).map_err(|_| unreadable());
        plain.zeroize();
        secrets.map(Some)
    }

    /// Seal and write the secrets: temp file, then rename.
    pub fn save(&self, secrets: &Secrets) -> Result<(), String> {
        let key = self.sealing_key(true)?;
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "Windows would not give WattWall random bytes.".to_string())?;
        let mut sealed = serde_json::to_vec(secrets).map_err(|err| err.to_string())?;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut sealed,
        )
        .map_err(|_| "Could not encrypt WattWall's secrets.".to_string())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
        }
        let tmp = self.path.with_extension("bin.tmp");
        std::fs::write(&tmp, &out).map_err(|err| err.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|err| err.to_string())
    }

    /// Delete the file. The Credential Manager key stays: a key without a file
    /// protects nothing, and `--cleanup` removes it with [`forget_key`].
    pub fn clear(&self) -> Result<(), String> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("Could not remove WattWall's secrets: {err}")),
        }
    }

    fn sealing_key(&self, create: bool) -> Result<LessSafeKey, String> {
        let mut bytes = match &self.key {
            KeySource::Fixed(key) => *key,
            KeySource::CredentialManager => stored_key(create)?,
        };
        let key = UnboundKey::new(&AES_256_GCM, &bytes)
            .map_err(|_| "WattWall's vault key is the wrong size.".to_string());
        bytes.zeroize();
        Ok(LessSafeKey::new(key?))
    }
}

fn unreadable() -> String {
    "WattWall's secrets file could not be decrypted. Remove the VirusTotal key in Settings and save it again."
        .to_string()
}

/// The Credential Manager key, read once per process. `create` makes one when
/// there is none; without it, a missing key is an error.
fn stored_key(create: bool) -> Result<[u8; 32], String> {
    let mut cached = KEY.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(key) = *cached {
        return Ok(key);
    }
    let key = match read_key()? {
        Some(key) => key,
        None if create => {
            let mut key = [0u8; 32];
            SystemRandom::new()
                .fill(&mut key)
                .map_err(|_| "Windows would not give WattWall random bytes.".to_string())?;
            write_key(&key)?;
            key
        }
        None => return Err(unreadable()),
    };
    *cached = Some(key);
    Ok(key)
}

fn read_key() -> Result<Option<[u8; 32]>, String> {
    let target = HSTRING::from(TARGET);
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    if let Err(err) = unsafe { CredReadW(&target, CRED_TYPE_GENERIC, None, &mut credential) } {
        if err.code() == ERROR_NOT_FOUND.to_hresult() {
            return Ok(None);
        }
        return Err(format!(
            "Could not read WattWall's key from Credential Manager: {err}"
        ));
    }
    // SAFETY: CredReadW succeeded, so `credential` points at a CREDENTIALW
    // whose blob stays valid until CredFree.
    let key = unsafe {
        let blob = std::slice::from_raw_parts(
            (*credential).CredentialBlob,
            (*credential).CredentialBlobSize as usize,
        );
        let key = <[u8; 32]>::try_from(blob).ok();
        CredFree(credential.cast());
        key
    };
    key.map(Some)
        .ok_or_else(|| "WattWall's key in Credential Manager is the wrong size.".to_string())
}

fn write_key(key: &[u8; 32]) -> Result<(), String> {
    let mut target: Vec<u16> = TARGET.encode_utf16().chain(Some(0)).collect();
    let mut user: Vec<u16> = "WattWall".encode_utf16().chain(Some(0)).collect();
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_mut_ptr()),
        CredentialBlobSize: 32,
        CredentialBlob: key.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: PWSTR(user.as_mut_ptr()),
        ..Default::default()
    };
    unsafe { CredWriteW(&credential, 0) }
        .map_err(|err| format!("Could not save WattWall's key in Credential Manager: {err}"))
}

/// Remove the Credential Manager key, for `--cleanup`. Safe to run twice.
pub fn forget_key() -> Result<(), String> {
    if let Ok(mut cached) = KEY.lock() {
        *cached = None;
    }
    let target = HSTRING::from(TARGET);
    match unsafe { CredDeleteW(&target, CRED_TYPE_GENERIC, None) } {
        Ok(()) => Ok(()),
        Err(err) if err.code() == ERROR_NOT_FOUND.to_hresult() => Ok(()),
        Err(err) => Err(format!(
            "Could not remove WattWall's key from Credential Manager: {err}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wattwall-vault-{}-{name}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join(FILE)
    }

    fn secrets(key: &str) -> Secrets {
        Secrets {
            virustotal_key: Some(key.to_string()),
        }
    }

    #[test]
    fn round_trip_without_the_secret_in_the_file() {
        let path = temp_file("roundtrip");
        let vault = Vault::with_key(path.clone(), [7; 32]);
        assert!(vault.load().expect("absent is fine").is_none());
        vault.save(&secrets("abc123secret")).expect("save");
        let bytes = std::fs::read(&path).expect("written");
        assert!(!bytes.windows(12).any(|window| window == b"abc123secret"));
        let loaded = vault.load().expect("load").expect("present");
        assert_eq!(loaded.virustotal_key.as_deref(), Some("abc123secret"));
        vault.clear().expect("clear");
        vault.clear().expect("clearing twice is fine");
        assert!(!path.exists());
    }

    #[test]
    fn a_wrong_key_a_changed_byte_or_a_short_file_is_refused() {
        let path = temp_file("tamper");
        Vault::with_key(path.clone(), [7; 32])
            .save(&secrets("value"))
            .expect("save");
        assert!(
            Vault::with_key(path.clone(), [8; 32]).load().is_err(),
            "wrong key"
        );
        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, &bytes).expect("tamper");
        assert!(
            Vault::with_key(path.clone(), [7; 32]).load().is_err(),
            "changed byte"
        );
        std::fs::write(&path, &bytes[..20]).expect("truncate");
        assert!(
            Vault::with_key(path.clone(), [7; 32]).load().is_err(),
            "short file"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn each_save_uses_a_fresh_nonce() {
        let path = temp_file("nonce");
        let vault = Vault::with_key(path.clone(), [9; 32]);
        vault.save(&secrets("same")).expect("save");
        let first = std::fs::read(&path).expect("read");
        vault.save(&secrets("same")).expect("save");
        let second = std::fs::read(&path).expect("read");
        assert_ne!(first, second);
        let _ = std::fs::remove_file(&path);
    }
}
