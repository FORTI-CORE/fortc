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
    pub api_keys: std::collections::HashMap<String, String>,
    pub scan_subdomains: bool,
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
            api_keys: std::collections::HashMap::new(),
            scan_subdomains: false,
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

/// Show the current configuration
pub fn show_config(verbose: bool) -> FortiCoreResult<()> {
    use colored::*;

    let config = load_config()?;

    println!("{}", "=== FortiCore Configuration ===".bright_cyan());
    println!("User Agent: {}", config.user_agent.bright_white());
    println!(
        "Timeout: {} seconds",
        config.timeout.to_string().bright_white()
    );
    println!(
        "Default Scan Type: {}",
        config.default_scan_type.bright_white()
    );
    println!(
        "Reports Directory: {}",
        config.reports_dir.display().to_string().bright_white()
    );
    println!(
        "Scans Directory: {}",
        config.scans_dir.display().to_string().bright_white()
    );
    println!("Safe Mode: {}", config.safe_mode.to_string().bright_white());
    println!(
        "Max Threads: {}",
        config.max_threads.to_string().bright_white()
    );
    println!(
        "Subdomain Scanning: {}",
        config.scan_subdomains.to_string().bright_white()
    );

    // Display API keys
    if !config.api_keys.is_empty() {
        println!("\n{}", "API Keys:".bright_yellow());
        for (service, _) in &config.api_keys {
            println!("  {}: {}", service.bright_white(), "[Set]".bright_green());
        }
    } else {
        println!("\n{}", "API Keys: None configured".bright_yellow());
    }

    if verbose {
        println!("\n{}", "Configuration Paths:".bright_yellow());
        println!("  /etc/forticore/config.json");
        println!("  ~/.config/forticore/config.json");
        println!("  ./forticore.json");
    }

    Ok(())
}

/// Set an API key in the configuration
pub fn set_api_key(service: &str, key: &str, verbose: bool) -> FortiCoreResult<()> {
    use colored::*;
    use std::collections::HashMap;

    let config_path = PathBuf::from("./forticore.json");
    let mut config = load_config()?;

    // Update the API key in the config
    config.api_keys.insert(service.to_string(), key.to_string());

    // Save updated config
    save_config(&config, &config_path)?;

    if verbose {
        println!(
            "{} {} {}",
            "API key for".bright_green(),
            service.bright_white(),
            "saved successfully".bright_green()
        );
    }

    Ok(())
}

/// Set the default scan type
pub fn set_default_scan_type(scan_type: &str, verbose: bool) -> FortiCoreResult<()> {
    use colored::*;

    let config_path = PathBuf::from("./forticore.json");
    let mut config = load_config()?;

    config.default_scan_type = scan_type.to_lowercase();

    // Save updated config
    save_config(&config, &config_path)?;

    if verbose {
        println!(
            "{} {}",
            "Default scan type set to:".bright_green(),
            scan_type.bright_white()
        );
    }

    Ok(())
}

/// Set the default subdomain scanning option
pub fn set_default_subdomain_scanning(enabled: bool, verbose: bool) -> FortiCoreResult<()> {
    use colored::*;

    let config_path = PathBuf::from("./forticore.json");
    let mut config = load_config()?;

    // Update the subdomain scanning setting
    config.scan_subdomains = enabled;

    // Save updated config
    save_config(&config, &config_path)?;

    if verbose {
        println!(
            "{} {}",
            "Default subdomain scanning set to:".bright_green(),
            enabled.to_string().bright_white()
        );
    }

    Ok(())
}
