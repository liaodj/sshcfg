use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::BaseDirs;
use serde::Serialize;

use crate::fs::writer;

pub const MANAGED_BLOCK_START: &str = "# >>> sshcfg managed include >>>";
pub const MANAGED_BLOCK_END: &str = "# <<< sshcfg managed include <<<";
pub const MANAGED_INCLUDE_LINE: &str = "Include ~/.ssh/config.d/*";

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub ssh_dir: PathBuf,
    pub root_config: PathBuf,
    pub config_d_dir: PathBuf,
    pub app_dir: PathBuf,
    pub backups_dir: PathBuf,
    pub state_file: PathBuf,
}

#[derive(Debug, Serialize)]
struct AppState {
    version: u32,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let base = BaseDirs::new().context("failed to resolve home directory")?;
        let ssh_dir = base.home_dir().join(".ssh");
        let app_dir = ssh_dir.join(".sshcfg");

        Ok(Self {
            root_config: ssh_dir.join("config"),
            config_d_dir: ssh_dir.join("config.d"),
            backups_dir: app_dir.join("backups"),
            state_file: app_dir.join("state.toml"),
            ssh_dir,
            app_dir,
        })
    }

    pub fn ensure_base_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.ssh_dir)?;
        std::fs::create_dir_all(&self.config_d_dir)?;
        std::fs::create_dir_all(&self.app_dir)?;
        std::fs::create_dir_all(&self.backups_dir)?;
        Ok(())
    }

    pub fn ensure_state_file(&self) -> Result<()> {
        if self.state_file.exists() {
            return Ok(());
        }

        let state = AppState { version: 1 };
        let content = toml::to_string_pretty(&state)?;
        writer::write_text_file(&self.state_file, &content)?;
        Ok(())
    }

    pub fn managed_config_path(&self) -> PathBuf {
        self.app_dir.join("ssh-g-managed.conf")
    }

    pub fn managed_match_config_path(&self) -> PathBuf {
        self.app_dir.join("ssh-g-managed-with-match.conf")
    }

    pub fn managed_entry_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        if !self.config_d_dir.exists() {
            return Ok(files);
        }

        for item in std::fs::read_dir(&self.config_d_dir)? {
            let item = item?;
            let path = item.path();
            if path.extension().and_then(|value| value.to_str()) == Some("conf") {
                files.push(path);
            }
        }

        files.sort();
        Ok(files)
    }
}

pub fn platform_newline() -> &'static str {
    if cfg!(windows) { "\r\n" } else { "\n" }
}

pub fn detect_newline(content: &str) -> &'static str {
    if content.contains("\r\n") {
        "\r\n"
    } else {
        platform_newline()
    }
}

pub fn managed_block(newline: &str) -> String {
    format!(
        "{MANAGED_BLOCK_START}{newline}{MANAGED_INCLUDE_LINE}{newline}{MANAGED_BLOCK_END}{newline}"
    )
}

pub fn has_managed_block(content: &str) -> bool {
    content.contains(MANAGED_BLOCK_START) && content.contains(MANAGED_BLOCK_END)
}

pub fn has_include_line(content: &str) -> bool {
    content
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case(MANAGED_INCLUDE_LINE))
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}
