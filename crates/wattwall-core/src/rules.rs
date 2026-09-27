//! Identity of the firewall rules WattWall creates. Anything that does not
//! match is left alone, including a rule a person put in the WattWall group
//! by hand.

use sha2::{Digest, Sha256};

pub const GROUP: &str = "WattWall";
pub const MARKER: &str = "WattWall v1";
/// Block All: one outbound and one inbound rule with no program, so they
/// apply to every program. Block rules win over allow rules in Windows.
pub const BLOCK_ALL_OUT: &str = "WattWall Block All Out";
pub const BLOCK_ALL_IN: &str = "WattWall Block All In";

/// Outbound name, then inbound name. The hash is of the lower-cased path so
/// `Curl.exe` and `curl.exe` are the same program on Windows.
pub fn rule_names(path: &str) -> (String, String) {
    let hash = hash16(path);
    (
        format!("WattWall Out {hash}"),
        format!("WattWall In {hash}"),
    )
}

pub fn is_our_rule(grouping: &str, description: &str, name: &str) -> bool {
    grouping == GROUP
        && description == MARKER
        && (name.starts_with("WattWall Out ")
            || name.starts_with("WattWall In ")
            || name == BLOCK_ALL_OUT
            || name == BLOCK_ALL_IN)
}

fn hash16(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.trim().to_ascii_lowercase().as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_stable_and_case_insensitive() {
        let (out, inn) = rule_names(r"C:\Windows\System32\curl.exe");
        assert_eq!(
            rule_names(r"C:\windows\system32\CURL.EXE"),
            (out.clone(), inn.clone())
        );
        assert!(out.starts_with("WattWall Out "));
        assert!(inn.starts_with("WattWall In "));
        assert_ne!(out, inn);
        assert_ne!(
            rule_names(r"C:\Windows\System32\curl.exe"),
            rule_names(r"C:\Tools\curl.exe")
        );
    }

    #[test]
    fn only_marked_rules_are_ours() {
        let (out, _) = rule_names(r"C:\Windows\System32\curl.exe");
        assert!(is_our_rule(GROUP, MARKER, &out));
        assert!(!is_our_rule("WattWall", "I made this", &out));
        assert!(!is_our_rule("Other", MARKER, &out));
        assert!(!is_our_rule(GROUP, MARKER, "Block curl"));
    }

    #[test]
    fn block_all_rules_are_ours_only_by_their_exact_names() {
        assert!(is_our_rule(GROUP, MARKER, BLOCK_ALL_OUT));
        assert!(is_our_rule(GROUP, MARKER, BLOCK_ALL_IN));
        assert!(!is_our_rule(GROUP, "I made this", BLOCK_ALL_OUT));
        assert!(!is_our_rule(GROUP, MARKER, "WattWall Block All"));
        assert!(!is_our_rule(GROUP, MARKER, "WattWall Block All Out 2"));
    }
}
