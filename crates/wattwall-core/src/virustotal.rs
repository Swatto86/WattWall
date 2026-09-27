//! VirusTotal hash lookups, without the network: what a report says, when a
//! file is due for another look, and pacing requests under the free API
//! limits (4 a minute, 500 a day). Only a file's SHA-256 is ever sent.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A found file is looked up again after a week, since engines change their
/// verdicts; a file VirusTotal has never seen is tried again after a day.
pub const RECHECK_FOUND: i64 = 7 * 24 * 60 * 60;
pub const RECHECK_UNKNOWN: i64 = 24 * 60 * 60;

/// At most this many detections are kept to show, most engines agree anyway.
const NAMES_KEPT: usize = 12;

/// What VirusTotal's engines said about one file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub malicious: u32,
    pub suspicious: u32,
    /// Engines that gave a verdict: malicious, suspicious, harmless or undetected.
    pub engines: u32,
    /// "Engine: detection" for the engines that flagged it.
    pub names: Vec<String>,
}

/// The answer to one lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Lookup {
    Found(Report),
    /// VirusTotal has no record of this file.
    Unknown,
}

/// A lookup and when it was made (Unix seconds).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checked {
    pub checked_at: i64,
    pub lookup: Lookup,
}

/// Whether a file needs a (new) lookup.
pub fn is_due(checked: Option<&Checked>, now: i64) -> bool {
    match checked {
        None => true,
        Some(checked) => {
            let age = now.saturating_sub(checked.checked_at);
            match checked.lookup {
                Lookup::Found(_) => age >= RECHECK_FOUND,
                Lookup::Unknown => age >= RECHECK_UNKNOWN,
            }
        }
    }
}

/// A SHA-256 as VirusTotal takes it: 64 lowercase hex digits.
pub fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// VirusTotal API keys are 64 hex digits. Returns the trimmed key.
pub fn api_key(text: &str) -> Option<String> {
    let key = text.trim();
    (key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())).then(|| key.to_string())
}

/// The report inside a `GET /api/v3/files/{sha256}` answer.
pub fn parse_report(body: &str) -> Result<Report, String> {
    let root: Value = serde_json::from_str(body)
        .map_err(|err| format!("VirusTotal sent unreadable JSON: {err}"))?;
    let attributes = root
        .pointer("/data/attributes")
        .ok_or("VirusTotal's answer has no file attributes.")?;
    let stats = attributes
        .get("last_analysis_stats")
        .ok_or("VirusTotal's answer has no analysis counts.")?;
    let count = |name: &str| {
        stats
            .get(name)
            .and_then(Value::as_u64)
            .map_or(0, |value| u32::try_from(value).unwrap_or(u32::MAX))
    };
    let malicious = count("malicious");
    let suspicious = count("suspicious");
    let engines = malicious
        .saturating_add(suspicious)
        .saturating_add(count("harmless"))
        .saturating_add(count("undetected"));
    let mut names: Vec<String> = attributes
        .get("last_analysis_results")
        .and_then(Value::as_object)
        .map(|results| {
            results
                .iter()
                .filter_map(|(engine, verdict)| {
                    let category = verdict.get("category").and_then(Value::as_str)?;
                    if category != "malicious" && category != "suspicious" {
                        return None;
                    }
                    let result = verdict
                        .get("result")
                        .and_then(Value::as_str)
                        .unwrap_or(category);
                    Some(format!("{engine}: {result}"))
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort_by_key(|name| name.to_ascii_lowercase());
    names.truncate(NAMES_KEPT);
    Ok(Report {
        malicious,
        suspicious,
        engines,
        names,
    })
}

/// How many lookups the owner's key may make. Keys differ, so these are set
/// when the check is turned on, starting from the free Public API's limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub per_minute: u32,
    pub per_day: u32,
}

impl Limits {
    /// VirusTotal's free Public API: 4 lookups a minute, 500 a day.
    pub const FREE: Self = Self {
        per_minute: 4,
        per_day: 500,
    };

    pub fn new(per_minute: u32, per_day: u32) -> Result<Self, String> {
        if !(1..=10_000).contains(&per_minute) {
            return Err("Lookups per minute must be between 1 and 10,000.".into());
        }
        if !(1..=10_000_000).contains(&per_day) {
            return Err("Lookups per day must be between 1 and 10,000,000.".into());
        }
        Ok(Self {
            per_minute,
            per_day,
        })
    }

    /// Seconds between lookups that keep within the per-minute limit.
    pub fn spacing(&self) -> i64 {
        let per_minute = i64::from(self.per_minute.max(1));
        (60 + per_minute - 1) / per_minute
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::FREE
    }
}

/// One of a key's quotas: how many requests it allows and has used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Quota {
    pub allowed: u64,
    pub used: u64,
}

/// A key's quotas as VirusTotal reports them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Quotas {
    pub hourly: Option<Quota>,
    pub daily: Option<Quota>,
    pub monthly: Option<Quota>,
}

impl Quotas {
    /// Limits that stay inside these quotas: the daily allowance, and a
    /// sixtieth of the hourly one a minute (4 for the free Public API's 240).
    pub fn limits(&self) -> Option<Limits> {
        let daily = self.daily?;
        let per_minute = self.hourly.map_or(Limits::FREE.per_minute, |hourly| {
            (hourly.allowed / 60).max(1) as u32
        });
        Limits::new(
            per_minute.min(10_000),
            u32::try_from(daily.allowed)
                .unwrap_or(u32::MAX)
                .clamp(1, 10_000_000),
        )
        .ok()
    }
}

/// The quotas in a `/users/{id}/overall_quotas` or `/users/{id}` answer. Both
/// shapes are accepted: `{"api_requests_daily": {"user": {"allowed": ..}}}` and
/// `{"attributes": {"quotas": {"api_requests_daily": {"allowed": ..}}}}`.
pub fn parse_quotas(body: &str) -> Result<Quotas, String> {
    let root: Value = serde_json::from_str(body)
        .map_err(|err| format!("VirusTotal sent unreadable JSON: {err}"))?;
    let data = root.get("data").ok_or("VirusTotal's answer has no data.")?;
    let table = data.pointer("/attributes/quotas").unwrap_or(data);
    let quota = |name: &str| {
        let entry = table.get(name)?;
        let entry = entry.get("user").unwrap_or(entry);
        Some(Quota {
            allowed: entry.get("allowed")?.as_u64()?,
            used: entry.get("used").and_then(Value::as_u64).unwrap_or(0),
        })
    };
    let quotas = Quotas {
        hourly: quota("api_requests_hourly"),
        daily: quota("api_requests_daily"),
        monthly: quota("api_requests_monthly"),
    };
    if quotas.daily.is_none() && quotas.hourly.is_none() {
        return Err("VirusTotal's answer has no request quotas.".into());
    }
    Ok(quotas)
}

/// VirusTotal's own words from an error answer: `{"error": {"code", "message"}}`.
pub fn error_reason(body: &str) -> Option<String> {
    let root: Value = serde_json::from_str(body).ok()?;
    let error = root.get("error")?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let text = match (message.is_empty(), code.is_empty()) {
        (false, _) => message,
        (true, false) => code,
        (true, true) => return None,
    };
    Some(text.chars().take(160).collect())
}

/// Spaces lookups within the owner's limits and backs off when VirusTotal
/// says the quota is used up. Times are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pacer {
    spacing: i64,
    daily: u32,
    day: i64,
    used_today: u32,
    last: Option<i64>,
    paused_until: i64,
    limited_in_a_row: u32,
}

impl Pacer {
    pub fn for_limits(limits: Limits, day: i64, used_today: u32) -> Self {
        Self::new(limits.spacing(), limits.per_day, day, used_today)
    }

    pub fn new(spacing: i64, daily: u32, day: i64, used_today: u32) -> Self {
        Self {
            spacing,
            daily,
            day,
            used_today,
            last: None,
            paused_until: 0,
            limited_in_a_row: 0,
        }
    }

    /// The UTC day number and how many lookups it has used, for saving.
    pub fn usage(&self) -> (i64, u32) {
        (self.day, self.used_today)
    }

    /// Seconds until the next lookup may go; 0 means now.
    pub fn wait(&self, now: i64) -> i64 {
        let today = now.div_euclid(86_400);
        if today == self.day && self.used_today >= self.daily {
            return (today + 1) * 86_400 - now;
        }
        let spaced = self.last.map_or(0, |last| last + self.spacing - now);
        spaced.max(self.paused_until - now).max(0)
    }

    pub fn sent(&mut self, now: i64) {
        let today = now.div_euclid(86_400);
        if today != self.day {
            self.day = today;
            self.used_today = 0;
        }
        self.used_today = self.used_today.saturating_add(1);
        self.last = Some(now);
    }

    /// VirusTotal answered normally.
    pub fn answered(&mut self) {
        self.limited_in_a_row = 0;
    }

    /// VirusTotal said the quota is used up: wait five minutes, and an hour
    /// once that has happened three times running (the daily quota).
    pub fn limited(&mut self, now: i64) {
        self.limited_in_a_row = self.limited_in_a_row.saturating_add(1);
        let pause = if self.limited_in_a_row >= 3 {
            3_600
        } else {
            300
        };
        self.pause(now, pause);
    }

    pub fn pause(&mut self, now: i64, seconds: i64) {
        self.paused_until = self.paused_until.max(now + seconds);
    }

    /// Forget a pause, for example after a new key is saved.
    pub fn resume(&mut self) {
        self.paused_until = 0;
        self.limited_in_a_row = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{"data":{"id":"x","type":"file","attributes":{
        "last_analysis_stats":{"malicious":2,"suspicious":1,"undetected":60,"harmless":7,"timeout":3,"type-unsupported":4},
        "last_analysis_results":{
            "Zeta":{"category":"malicious","engine_name":"Zeta","result":"Trojan.Win32.Test"},
            "alpha":{"category":"suspicious","engine_name":"alpha","result":null},
            "Beta":{"category":"undetected","engine_name":"Beta","result":null},
            "Gamma":{"category":"malicious","engine_name":"Gamma","result":"Gen:Variant"}
        }}}}"#;

    #[test]
    fn reads_counts_and_the_engines_that_flagged_it() {
        let report = parse_report(REPORT).expect("valid report");
        assert_eq!(report.malicious, 2);
        assert_eq!(report.suspicious, 1);
        assert_eq!(
            report.engines, 70,
            "timeouts and unsupported types are not verdicts"
        );
        assert_eq!(
            report.names,
            vec![
                "alpha: suspicious".to_string(),
                "Gamma: Gen:Variant".to_string(),
                "Zeta: Trojan.Win32.Test".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_answers_that_are_not_file_reports() {
        assert!(parse_report("not json").is_err());
        assert!(parse_report(r#"{"error":{"code":"NotFoundError"}}"#).is_err());
        assert!(parse_report(r#"{"data":{"attributes":{}}}"#).is_err());
    }

    #[test]
    fn a_clean_file_has_no_names() {
        let body = r#"{"data":{"attributes":{"last_analysis_stats":{"undetected":72},"last_analysis_results":{}}}}"#;
        let report = parse_report(body).expect("valid report");
        assert_eq!(
            (report.malicious, report.engines, report.names.len()),
            (0, 72, 0)
        );
    }

    #[test]
    fn found_files_are_rechecked_weekly_and_unknown_ones_daily() {
        let found = Checked {
            checked_at: 1_000,
            lookup: Lookup::Found(Report::default()),
        };
        let unknown = Checked {
            checked_at: 1_000,
            lookup: Lookup::Unknown,
        };
        assert!(is_due(None, 0));
        assert!(!is_due(Some(&found), 1_000 + RECHECK_UNKNOWN));
        assert!(is_due(Some(&found), 1_000 + RECHECK_FOUND));
        assert!(!is_due(Some(&unknown), 1_000 + RECHECK_UNKNOWN - 1));
        assert!(is_due(Some(&unknown), 1_000 + RECHECK_UNKNOWN));
    }

    #[test]
    fn keys_and_hashes() {
        let key = format!("  {}\n", "aB3".repeat(21) + "c");
        assert_eq!(
            api_key(&key).as_deref(),
            Some(("aB3".repeat(21) + "c").as_str())
        );
        assert_eq!(api_key("short"), None);
        assert_eq!(api_key(&"g".repeat(64)), None);
        assert!(is_sha256(&"0a".repeat(32)));
        assert!(!is_sha256(&"0A".repeat(32)), "lowercase only");
        assert!(!is_sha256(&"0a".repeat(31)));
    }

    #[test]
    fn lookups_are_spaced_and_capped_per_day() {
        let day = 20_000;
        let now = day * 86_400 + 100;
        let mut pacer = Pacer::for_limits(Limits::FREE, day, 0);
        assert_eq!(pacer.wait(now), 0);
        pacer.sent(now);
        assert_eq!(pacer.wait(now), 15, "4 a minute is one every 15 seconds");
        assert_eq!(pacer.wait(now + 15), 0);
        let mut full = Pacer::for_limits(Limits::FREE, day, 500);
        assert_eq!(
            full.wait(now),
            86_400 - 100,
            "the daily cap waits for tomorrow"
        );
        full.sent((day + 1) * 86_400);
        assert_eq!(full.usage(), (day + 1, 1), "a new day starts a new count");
        let mut one_a_day = Pacer::for_limits(Limits::new(1, 1).expect("valid"), day, 0);
        one_a_day.sent(now);
        assert_eq!(
            one_a_day.wait(now + 60),
            86_400 - 160,
            "one a day means one a day"
        );
    }

    #[test]
    fn limits_are_checked_and_turned_into_spacing() {
        assert_eq!(Limits::default(), Limits::FREE);
        assert_eq!(Limits::FREE.spacing(), 15);
        assert_eq!(Limits::new(1, 1).expect("valid").spacing(), 60);
        assert_eq!(
            Limits::new(7, 100).expect("valid").spacing(),
            9,
            "rounds up to stay under"
        );
        assert_eq!(Limits::new(1_000, 100).expect("valid").spacing(), 1);
        assert!(Limits::new(0, 500).is_err());
        assert!(Limits::new(4, 0).is_err());
        assert!(Limits::new(10_001, 500).is_err());
    }

    #[test]
    fn quota_answers_back_off_and_a_resume_clears_them() {
        let mut pacer = Pacer::new(0, 500, 0, 0);
        pacer.limited(1_000);
        assert_eq!(pacer.wait(1_000), 300);
        pacer.limited(1_000);
        pacer.limited(1_000);
        assert_eq!(pacer.wait(1_000), 3_600);
        pacer.resume();
        assert_eq!(pacer.wait(1_000), 0);
        pacer.limited(2_000);
        pacer.answered();
        pacer.limited(2_000);
        assert_eq!(
            pacer.wait(2_000),
            300,
            "a normal answer resets the run of limits"
        );
    }

    #[test]
    fn quotas_in_both_shapes_and_the_limits_they_allow() {
        let overall = r#"{"data":{"api_requests_hourly":{"user":{"allowed":240,"used":3}},
            "api_requests_daily":{"user":{"allowed":500,"used":12}},
            "api_requests_monthly":{"user":{"allowed":15500,"used":40}}}}"#;
        let quotas = parse_quotas(overall).expect("overall quotas");
        assert_eq!(
            quotas.daily,
            Some(Quota {
                allowed: 500,
                used: 12
            })
        );
        assert_eq!(quotas.limits(), Some(Limits::FREE));
        let user =
            r#"{"data":{"attributes":{"quotas":{"api_requests_daily":{"allowed":1,"used":1}}}}}"#;
        let quotas = parse_quotas(user).expect("user object");
        assert_eq!(
            quotas.daily,
            Some(Quota {
                allowed: 1,
                used: 1
            })
        );
        assert_eq!(quotas.hourly, None);
        assert_eq!(
            quotas.limits(),
            Some(Limits {
                per_minute: 4,
                per_day: 1
            }),
            "no hourly quota keeps the free per-minute rate"
        );
        assert!(parse_quotas(r#"{"data":{}}"#).is_err());
        assert!(parse_quotas("nope").is_err());
    }

    #[test]
    fn error_reasons_come_from_virustotal() {
        assert_eq!(
            error_reason(r#"{"error":{"code":"QuotaExceededError","message":"Quota exceeded"}}"#)
                .as_deref(),
            Some("Quota exceeded")
        );
        assert_eq!(
            error_reason(r#"{"error":{"code":"WrongCredentialsError"}}"#).as_deref(),
            Some("WrongCredentialsError")
        );
        assert_eq!(error_reason("<html>"), None);
    }

    #[test]
    fn lookups_survive_a_save() {
        let checked = Checked {
            checked_at: 5,
            lookup: Lookup::Found(Report {
                malicious: 1,
                suspicious: 0,
                engines: 70,
                names: vec!["A: B".into()],
            }),
        };
        let text = serde_json::to_string(&checked).expect("serialise");
        assert!(text.contains(r#""kind":"found""#), "{text}");
        assert_eq!(
            serde_json::from_str::<Checked>(&text).expect("read back"),
            checked
        );
        let unknown = serde_json::to_string(&Lookup::Unknown).expect("serialise");
        assert_eq!(unknown, r#"{"kind":"unknown"}"#);
    }
}
