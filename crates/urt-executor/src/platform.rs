//! Cross-platform helpers for host-side filesystem operations

use std::path::PathBuf;

/// Host temporary directory (cross-platform)
pub fn temp_dir() -> PathBuf {
    std::env::temp_dir()
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
