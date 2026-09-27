//! Programs whose block would break Windows or cut this PC off from the
//! others. The list is deliberate and short.

/// What WattWall must do before it creates rules for a program.
#[derive(Debug, PartialEq, Eq)]
pub enum Guard {
    /// No extra warning.
    Ok,
    /// The person has to confirm. The text is the warning.
    Confirm(&'static str),
    /// There is nothing a program rule can attach to.
    Impossible(&'static str),
}

pub fn guard(file_name: &str, is_self: bool, is_system: bool) -> Guard {
    if is_system || file_name.eq_ignore_ascii_case("System") {
        return Guard::Impossible(
            "System is part of Windows itself and has no program file, so a firewall rule cannot name it.",
        );
    }
    if is_self || file_name.eq_ignore_ascii_case("WattWall.exe") {
        return Guard::Confirm(
            "Blocking WattWall stops this app, including its update check, until you allow it again.",
        );
    }
    match file_name.to_ascii_lowercase().as_str() {
        "svchost.exe" => Guard::Confirm(
            "Blocking svchost.exe stops parts of Windows itself. Updates, networking and other services share this program.",
        ),
        "lsass.exe" => Guard::Confirm(
            "Blocking lsass.exe can sign you out or leave Windows unable to start properly.",
        ),
        "tailscaled.exe" | "tailscale-ipn.exe" => Guard::Confirm(
            "Blocking Tailscale disconnects this PC from your other machines.",
        ),
        _ => Guard::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warns_for_the_named_programs_only() {
        assert!(matches!(guard("curl.exe", false, false), Guard::Ok));
        assert!(matches!(
            guard("svchost.exe", false, false),
            Guard::Confirm(_)
        ));
        assert!(matches!(
            guard("SVCHOST.EXE", false, false),
            Guard::Confirm(_)
        ));
        assert!(matches!(
            guard("lsass.exe", false, false),
            Guard::Confirm(_)
        ));
        assert!(matches!(
            guard("tailscaled.exe", false, false),
            Guard::Confirm(_)
        ));
        assert!(matches!(
            guard("tailscale-ipn.exe", false, false),
            Guard::Confirm(_)
        ));
        assert!(matches!(
            guard("notepad.exe", true, false),
            Guard::Confirm(_)
        ));
        assert!(matches!(
            guard("WattWall.exe", false, false),
            Guard::Confirm(_)
        ));
        assert!(matches!(
            guard("System", false, false),
            Guard::Impossible(_)
        ));
        assert!(matches!(
            guard("ntoskrnl.exe", false, true),
            Guard::Impossible(_)
        ));
        assert!(matches!(guard("ssh.exe", false, false), Guard::Ok));
    }
}
