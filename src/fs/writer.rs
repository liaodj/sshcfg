use std::path::Path;

use anyhow::Result;
use chrono::Utc;

use crate::fs::layout::ensure_parent;

pub fn write_text_file(path: &Path, content: &str) -> Result<()> {
    write_bytes_file(path, content.as_bytes())
}

pub fn write_bytes_file(path: &Path, content: &[u8]) -> Result<()> {
    ensure_parent(path)?;

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("tmp");
    let temp_name = format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let temp_path = path.with_file_name(temp_name);

    std::fs::write(&temp_path, content)?;
    set_private_file_mode(&temp_path)?;

    if path.exists() {
        std::fs::remove_file(path)?;
    }

    std::fs::rename(temp_path, path)?;
    set_private_file_mode(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_mode(_path: &Path) -> Result<()> {
    Ok(())
}
