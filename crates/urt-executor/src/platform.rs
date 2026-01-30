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
