//! The I/O behind the VirusTotal check: hashing a program file and asking
//! VirusTotal about the hash. The debug build's test mode answers from a
//! fixed table instead of the network and notes every call in
//! `fake-virustotal-calls.log`.

use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wattwall_core::virustotal::{
    error_reason, is_sha256, parse_quotas, parse_report, Lookup, Quotas, Report,
};

/// A program file's SHA-256 and the size and date it was taken at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hashed {
    pub size: u64,
    pub modified: i64,
    pub sha256: String,
}

pub enum LookupError {
    KeyRejected,
    /// The quota is used up, in VirusTotal's words.
    Limited(String),
    Other(String),
}

/// Hash `path`, or return `cached` untouched when the file's size and date
/// have not changed since.
pub fn hash_file(path: &Path, cached: Option<&Hashed>) -> Result<Hashed, String> {
    let meta = std::fs::metadata(path).map_err(|err| err.to_string())?;
    if !meta.is_file() {
        return Err("not a file".into());
    }
    let modified = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    if let Some(cached) = cached {
        if cached.size == meta.len() && cached.modified == modified {
            return Ok(cached.clone());
        }
    }
    let mut file = std::fs::File::open(path).map_err(|err| err.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(Hashed {
        size: meta.len(),
        modified,
        sha256,
    })
}

fn client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    // Same provider the updater installs; whichever runs first wins.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("WattWall/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|err| err.to_string())?;
    Ok(CLIENT.get_or_init(|| client))
}

/// Ask VirusTotal about one hash. Only the hash and the key are sent.
pub fn lookup(sha256: &str, key: &str) -> Result<Lookup, LookupError> {
    if !is_sha256(sha256) {
        return Err(LookupError::Other("not a SHA-256".into()));
    }
    let client = client().map_err(LookupError::Other)?;
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let answer = tauri::async_runtime::block_on(async {
        let response = client.get(&url).header("x-apikey", key).send().await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        Ok::<_, reqwest::Error>((status, body))
    });
    let (status, body) = answer.map_err(|err| LookupError::Other(short_error(&err)))?;
    match status {
        200 => parse_report(&body)
            .map(Lookup::Found)
            .map_err(LookupError::Other),
        404 => Ok(Lookup::Unknown),
        401 | 403 => Err(LookupError::KeyRejected),
        429 => Err(LookupError::Limited(
            error_reason(&body).unwrap_or_else(|| "Quota exceeded".into()),
        )),
        other => Err(LookupError::Other(match error_reason(&body) {
            Some(reason) => format!("VirusTotal answered {other}: {reason}"),
            None => format!("VirusTotal answered {other}"),
        })),
    }
}

/// The key's request quotas. VirusTotal documents that these requests do not
/// count against the quota. The key is the account id here, so it appears in
/// the path as well as the header.
pub async fn quotas(key: &str) -> Result<Quotas, LookupError> {
    let client = client().map_err(LookupError::Other)?;
    let mut last = LookupError::Other("VirusTotal did not answer".into());
    for path in ["overall_quotas", ""] {
        let url = if path.is_empty() {
            format!("https://www.virustotal.com/api/v3/users/{key}")
        } else {
            format!("https://www.virustotal.com/api/v3/users/{key}/{path}")
        };
        let response = client
            .get(&url)
            .header("x-apikey", key)
            .send()
            .await
            .map_err(|err| LookupError::Other(short_error(&err)))?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|err| LookupError::Other(short_error(&err)))?;
        match status {
            200 => match parse_quotas(&body) {
                Ok(quotas) => return Ok(quotas),
                Err(err) => last = LookupError::Other(err),
            },
            401 | 403 => return Err(LookupError::KeyRejected),
            429 => {
                return Err(LookupError::Limited(
                    error_reason(&body).unwrap_or_default(),
                ))
            }
            other => {
                last = LookupError::Other(match error_reason(&body) {
                    Some(reason) => format!("VirusTotal answered {other}: {reason}"),
                    None => format!("VirusTotal answered {other}"),
                })
            }
        }
    }
    Err(last)
}

/// Test mode's quotas: the free Public API, 12 used today.
pub fn fake_quotas(key: &str) -> Result<Quotas, LookupError> {
    if key.bytes().all(|byte| byte == b'0') {
        return Err(LookupError::KeyRejected);
    }
    parse_quotas(
        r#"{"data":{"api_requests_hourly":{"user":{"allowed":240,"used":2}},"api_requests_daily":{"user":{"allowed":500,"used":12}}}}"#,
    )
    .map_err(LookupError::Other)
}

fn short_error(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        "timed out".into()
    } else if err.is_connect() {
        "no connection".into()
    } else {
        "network error".into()
    }
}

/// Test mode: curl.exe is flagged, notepad.exe is clean, anything else is
/// unknown, and an all-zero key is rejected.
pub fn fake_lookup(dir: &Path, path: &str, sha256: &str, key: &str) -> Result<Lookup, LookupError> {
    if key.bytes().all(|byte| byte == b'0') {
        return Err(LookupError::KeyRejected);
    }
    use std::io::Write;
    let log = dir.join("fake-virustotal-calls.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
    {
        let _ = writeln!(file, "{sha256}");
    }
    let name = Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    Ok(match name.as_str() {
        "curl.exe" => Lookup::Found(Report {
            malicious: 3,
            suspicious: 1,
            engines: 70,
            names: vec![
                "Alpha: Trojan.Test".into(),
                "Beta: Suspicious.Gen".into(),
                "Gamma: Malware.Probe".into(),
                "Delta: Heur.Test".into(),
            ],
        }),
        "notepad.exe" => Lookup::Found(Report {
            malicious: 0,
            suspicious: 0,
            engines: 70,
            names: Vec::new(),
        }),
        _ => Lookup::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live check of the real request: TLS, header and answer handling.
    /// `cargo test -p wattwall-desktop live_ -- --ignored`
    #[test]
    #[ignore = "talks to virustotal.com"]
    fn live_virustotal_rejects_a_made_up_key() {
        let eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        let answer = lookup(eicar, &"0".repeat(64));
        assert!(matches!(answer, Err(LookupError::KeyRejected)));
    }

    #[test]
    #[ignore = "talks to virustotal.com"]
    fn live_virustotal_quota_request_rejects_a_made_up_key() {
        let answer = tauri::async_runtime::block_on(quotas(&"0".repeat(64)));
        assert!(matches!(answer, Err(LookupError::KeyRejected)));
    }

    #[test]
    fn hashes_a_file_and_skips_rereading_an_unchanged_one() {
        let dir = std::env::temp_dir().join(format!("wattwall-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("probe.bin");
        std::fs::write(&path, b"abc").expect("write");
        let hashed = hash_file(&path, None).expect("hash");
        assert_eq!(
            hashed.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hashed.size, 3);
        let pretend = Hashed {
            sha256: "0".repeat(64),
            ..hashed.clone()
        };
        assert_eq!(
            hash_file(&path, Some(&pretend)).expect("hash").sha256,
            "0".repeat(64),
            "same size and date: the cached hash is trusted"
        );
        std::fs::write(&path, b"abcd").expect("rewrite");
        assert_ne!(
            hash_file(&path, Some(&pretend)).expect("hash").sha256,
            "0".repeat(64)
        );
        assert!(hash_file(&dir, None).is_err(), "a folder is not a program");
        assert!(hash_file(&dir.join("missing.exe"), None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
