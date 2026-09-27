//! Program-path checks that do not need the filesystem.

use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    #[error("Choose a program file.")]
    Empty,
    #[error("That path is not a program file WattWall can block.")]
    NotExe,
    #[error("WattWall needs the full path of the program, not a relative one.")]
    Relative,
}

/// Strip the `\\?\` prefix Windows adds when it canonicalises a path, so
/// firewall rules and the window show a normal path.
pub fn plain_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path.to_path_buf()
}

/// File name of an exe path, preserving the name's own casing.
pub fn exe_name(path: &str) -> Option<&str> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return None;
    }
    let name = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    if name.is_empty() {
        return None;
    }
    Some(name)
}

pub fn check_exe_path(path: &str) -> Result<(), PathError> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(PathError::Empty);
    }
    let name = exe_name(trimmed).ok_or(PathError::Empty)?;
    if !name.to_ascii_lowercase().ends_with(".exe") {
        return Err(PathError::NotExe);
    }
    let absolute = trimmed.starts_with(r"\\")
        || (trimmed.len() >= 3
            && trimmed.as_bytes()[1] == b':'
            && (trimmed.as_bytes()[2] == b'\\' || trimmed.as_bytes()[2] == b'/'));
    if !absolute {
        return Err(PathError::Relative);
    }
    Ok(())
}

/// `path` is strictly inside `root`, compared component by component so
/// `C:\Program Files Evil` is not inside `C:\Program Files`.
pub fn path_is_under(path: &Path, root: &Path) -> bool {
    let path = components(path);
    let root = components(root);
    path.len() > root.len() && path.starts_with(&root)
}

/// The only executable autostart is allowed to launch: the per-machine
/// install, after both paths have had junctions resolved by the caller.
pub fn is_installed_exe(final_exe: &Path, program_files: &Path) -> bool {
    if !path_is_under(final_exe, program_files) {
        return false;
    }
    let name = final_exe
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.eq_ignore_ascii_case("WattWall.exe"))
        .unwrap_or(false);
    let parent = final_exe
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|n| n.eq_ignore_ascii_case("WattWall"))
        .unwrap_or(false);
    name && parent
}

fn components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Prefix(prefix) => {
                Some(prefix.as_os_str().to_string_lossy().to_ascii_lowercase())
            }
            Component::RootDir => Some(String::new()),
            Component::Normal(part) => Some(part.to_string_lossy().to_ascii_lowercase()),
            Component::CurDir | Component::ParentDir => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_verbatim_prefix() {
        assert_eq!(
            plain_path(Path::new(r"\\?\C:\Program Files\WattWall\WattWall.exe")),
            PathBuf::from(r"C:\Program Files\WattWall\WattWall.exe")
        );
        assert_eq!(
            plain_path(Path::new(r"\\?\UNC\server\share\app.exe")),
            PathBuf::from(r"\\server\share\app.exe")
        );
    }

    #[test]
    fn rejects_non_exe_and_relative_paths() {
        assert_eq!(check_exe_path(""), Err(PathError::Empty));
        assert_eq!(check_exe_path(r"C:\a\notes.txt"), Err(PathError::NotExe));
        assert_eq!(check_exe_path(r"curl.exe"), Err(PathError::Relative));
        assert!(check_exe_path(r"C:\Windows\System32\curl.exe").is_ok());
        assert!(check_exe_path(r"\\server\share\app.exe").is_ok());
    }

    #[test]
    fn install_path_is_only_program_files_wattwall() {
        let root = Path::new(r"C:\Program Files");
        assert!(is_installed_exe(
            Path::new(r"C:\Program Files\WattWall\WattWall.exe"),
            root
        ));
        assert!(is_installed_exe(
            Path::new(r"C:\Program Files\wattwall\wattwall.exe"),
            root
        ));
        assert!(!is_installed_exe(
            Path::new(r"C:\Program Files Evil\WattWall\WattWall.exe"),
            root
        ));
        assert!(!is_installed_exe(
            Path::new(r"C:\Users\Swatto\WattWall.exe"),
            root
        ));
        assert!(!is_installed_exe(
            Path::new(r"C:\Program Files\WattWall\other.exe"),
            root
        ));
        assert!(!path_is_under(Path::new(r"C:\Program Files"), root));
    }
}
