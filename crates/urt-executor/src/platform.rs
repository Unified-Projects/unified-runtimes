//! Cross-platform helpers for host-side filesystem operations

use std::path::PathBuf;

/// Host temporary directory (cross-platform)
pub fn temp_dir() -> PathBuf {
    std::env::temp_dir()
}

/// Remove the Windows verbatim (`\\?\`) prefix that `canonicalize` returns.
///
/// The Docker daemon parses a bind-mount source itself and rejects a verbatim
/// path, so the canonical form has to be reduced to the ordinary one before it
/// is handed over. The prefix is kept when dropping it would change what the
/// path refers to: a path at or over the legacy 260-character limit, or one
/// whose components end in a dot or a space, is only addressable in verbatim
/// form.
#[cfg(windows)]
pub fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    use std::path::{Component, Prefix};

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path;
    };

    let root = match prefix.kind() {
        Prefix::VerbatimDisk(letter) => format!("{}:\\", letter as char),
        Prefix::VerbatimUNC(server, share) => format!(
            "\\\\{}\\{}\\",
            server.to_string_lossy(),
            share.to_string_lossy()
        ),
        _ => return path,
    };

    let mut plain = PathBuf::from(root);
    for component in components {
        match component {
            Component::RootDir => {}
            other => {
                let text = other.as_os_str().to_string_lossy();
                if text.ends_with('.') || text.ends_with(' ') {
                    return path;
                }
                plain.push(other.as_os_str());
            }
        }
    }

    if plain.as_os_str().len() >= 260 {
        return path;
    }

    plain
}

#[cfg(not(windows))]
pub fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    path
}

/// Set directory permissions to 0o777 (Unix) or no-op (Windows)
#[cfg(unix)]
pub async fn set_permissions_open(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).await
}

#[cfg(not(unix))]
pub async fn set_permissions_open(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Recursively set permissions on all files/dirs under `path`:
///   directories → 0o755, files → 0o644 (Unix only)
#[cfg(unix)]
pub async fn set_permissions_recursive(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let meta = tokio::fs::metadata(&p).await?;
        let mode = if meta.is_dir() { 0o755 } else { 0o644 };
        tokio::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).await?;
        if meta.is_dir() {
            let mut rd = tokio::fs::read_dir(&p).await?;
            while let Some(entry) = rd.next_entry().await? {
                stack.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn set_permissions_recursive(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod verbatim_prefix_tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn a_canonical_disk_path_loses_its_prefix() {
        assert_eq!(
            strip_verbatim_prefix(PathBuf::from(r"\\?\C:\Users\runner\Temp\exc1-fn")),
            PathBuf::from(r"C:\Users\runner\Temp\exc1-fn")
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_path_that_is_already_plain_is_returned_as_is() {
        assert_eq!(
            strip_verbatim_prefix(PathBuf::from(r"C:\Users\runner\Temp\exc1-fn")),
            PathBuf::from(r"C:\Users\runner\Temp\exc1-fn")
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_path_over_the_legacy_limit_keeps_its_prefix() {
        let long = format!(r"\\?\C:\{}", "segment\\".repeat(40));
        assert_eq!(
            strip_verbatim_prefix(PathBuf::from(&long)),
            PathBuf::from(&long)
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn posix_paths_are_untouched() {
        assert_eq!(
            strip_verbatim_prefix(PathBuf::from("/tmp/exc1-fn")),
            PathBuf::from("/tmp/exc1-fn")
        );
    }
}

// These tests assert Unix mode bits, which do not exist on other platforms.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn test_set_permissions_recursive_normalizes_files() {
        let tmp = std::env::temp_dir().join(format!(
            "urt_test_perms_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        tokio::fs::create_dir_all(&tmp).await.unwrap();

        // Create a file with unusual permissions
        let file_path = tmp.join("test.txt");
        tokio::fs::write(&file_path, b"hello").await.unwrap();
        tokio::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o777))
            .await
            .unwrap();

        // Create a subdirectory with unusual permissions
        let sub_dir = tmp.join("subdir");
        tokio::fs::create_dir_all(&sub_dir).await.unwrap();
        tokio::fs::set_permissions(&sub_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();

        set_permissions_recursive(&tmp).await.unwrap();

        let file_meta = tokio::fs::metadata(&file_path).await.unwrap();
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o644);

        let dir_meta = tokio::fs::metadata(&sub_dir).await.unwrap();
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o755);

        let root_meta = tokio::fs::metadata(&tmp).await.unwrap();
        assert_eq!(root_meta.permissions().mode() & 0o777, 0o755);

        tokio::fs::remove_dir_all(&tmp).await.ok();
    }

    #[tokio::test]
    async fn test_set_permissions_recursive_nested() {
        let tmp = std::env::temp_dir().join(format!(
            "urt_test_nested_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        tokio::fs::create_dir_all(&tmp).await.unwrap();

        // Build a nested tree: tmp/a/b/c/deep.txt
        let deep_dir = tmp.join("a").join("b").join("c");
        tokio::fs::create_dir_all(&deep_dir).await.unwrap();
        let deep_file = deep_dir.join("deep.txt");
        tokio::fs::write(&deep_file, b"deep").await.unwrap();
        tokio::fs::set_permissions(&deep_file, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
        tokio::fs::set_permissions(&deep_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();

        set_permissions_recursive(&tmp).await.unwrap();

        let file_meta = tokio::fs::metadata(&deep_file).await.unwrap();
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o644);

        let dir_meta = tokio::fs::metadata(&deep_dir).await.unwrap();
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o755);

        tokio::fs::remove_dir_all(&tmp).await.ok();
    }
}
