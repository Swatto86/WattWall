//! Decisions WattWall can explain without talking to Windows: which firewall
//! rules are ours, which programs need a warning, and how the window's list
//! is built from rules plus what has been seen on the network.

mod danger;
mod model;
mod pathutil;
mod rules;

pub use danger::{guard, Guard};
pub use model::{
    build_view, new_rules_enabled, remember, Remembered, Row, RuleRecord, View, REMEMBERED_CAP,
};
pub use pathutil::{
    check_exe_path, exe_name, is_installed_exe, path_is_under, plain_path, PathError,
};
pub use rules::{is_our_rule, rule_names, GROUP, MARKER};
