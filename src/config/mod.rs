use crate::utils::{error::FortiCoreResult, FortiCoreError};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortiCoreConfig {
    pub user_agent: String,
    pub timeout: u64,
    pub default_scan_type: String,
    pub reports_dir: PathBuf,
    pub scans_dir: PathBuf,
    pub safe_mode: bool,
    pub max_threads: usize,
}

impl Default for FortiCoreConfig {
    fn default() -> Self {
        FortiCoreConfig {
            user_agent: "FortiCore/0.1.0".to_string(),
            timeout: 10,
            default_scan_type: "basic".to_string(),
            reports_dir: PathBuf::from("/var/lib/forticore/reports"),
            scans_dir: PathBuf::from("/var/lib/forticore/scans"),
            safe_mode: true,
            max_threads: 10,
        }
    }
}

pub fn load_config() -> FortiCoreResult<FortiCoreConfig> {
    let config_paths = [
        PathBuf::from("/etc/forticore/config.json"),
        PathBuf::from("~/.config/forticore/config.json"),
        PathBuf::from("./forticore.json"),
    ];

    // Try to load from each path
    for path in &config_paths {
        if path.exists() {
            return load_config_from_file(path);
        }
    }

    // If no config exists, create a default one
    let config = FortiCoreConfig::default();
    save_config(&config, &config_paths[2])?;

    Ok(config)
}

fn load_config_from_file(path: &Path) -> FortiCoreResult<FortiCoreConfig> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let config: FortiCoreConfig = serde_json::from_str(&contents)
        .map_err(|e| FortiCoreError::ConfigError(format!("Failed to parse config: {}", e)))?;

    Ok(config)
}

pub fn save_config(config: &FortiCoreConfig, path: &Path) -> FortiCoreResult<()> {
    // Create directory if it doesn't exist
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(config)
        .map_err(|e| FortiCoreError::ConfigError(format!("Failed to serialize config: {}", e)))?;

    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}
