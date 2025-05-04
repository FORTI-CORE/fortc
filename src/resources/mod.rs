use crate::utils::error::{FortiCoreError, FortiCoreResult};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

// In-memory cache for loaded resources
static RESOURCE_CACHE: OnceLock<HashMap<String, Value>> = OnceLock::new();

/// Get the path to a resource file
pub fn get_resource_path(filename: &str) -> String {
    format!("src/resources/{}", filename)
}

/// Generic function to load a resource file and parse it
pub fn load_resource<T: DeserializeOwned>(filename: &str) -> FortiCoreResult<T> {
    // Try to get from cache first
    if let Some(cache) = RESOURCE_CACHE.get() {
        if let Some(value) = cache.get(filename) {
            if let Ok(parsed) = serde_json::from_value::<T>(value.clone()) {
                return Ok(parsed);
            }
        }
    }

    // Not in cache, load from file
    let path = get_resource_path(filename);
    let file_content = fs::read_to_string(&path).map_err(|e| {
        FortiCoreError::ResourceError(format!("Failed to read resource file {}: {}", path, e))
    })?;

    let value: Value = serde_json::from_str(&file_content).map_err(|e| {
        FortiCoreError::ResourceError(format!("Failed to parse resource file {}: {}", path, e))
    })?;

    // Cache the raw value
    let mut cache = RESOURCE_CACHE.get().cloned().unwrap_or_default();
    cache.insert(filename.to_string(), value.clone());
    if RESOURCE_CACHE.get().is_none() {
        let _ = RESOURCE_CACHE.set(cache);
    }

    // Parse into requested type
    let parsed = serde_json::from_value::<T>(value).map_err(|e| {
        FortiCoreError::ResourceError(format!(
            "Failed to deserialize resource file {} to target type: {}",
            path, e
        ))
    })?;

    Ok(parsed)
}

/// Load common subdomains list
pub fn load_subdomains() -> FortiCoreResult<Vec<String>> {
    let data: serde_json::Value = load_resource("subdomains.json")?;
    let subdomains = data["common_subdomains"]
        .as_array()
        .ok_or_else(|| {
            FortiCoreError::ResourceError(
                "Failed to find common_subdomains in subdomains.json".to_string(),
            )
        })?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    Ok(subdomains)
}

/// Load XSS payloads list
pub fn load_xss_payloads() -> FortiCoreResult<Vec<String>> {
    let data: serde_json::Value = load_resource("payloads.json")?;
    let payloads = data["xss_payloads"]
        .as_array()
        .ok_or_else(|| {
            FortiCoreError::ResourceError(
                "Failed to find xss_payloads in payloads.json".to_string(),
            )
        })?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    Ok(payloads)
}

/// Load SQL injection payloads list
pub fn load_sql_injection_payloads() -> FortiCoreResult<Vec<String>> {
    let data: serde_json::Value = load_resource("payloads.json")?;
    let payloads = data["sql_injection_payloads"]
        .as_array()
        .ok_or_else(|| {
            FortiCoreError::ResourceError(
                "Failed to find sql_injection_payloads in payloads.json".to_string(),
            )
        })?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    Ok(payloads)
}

/// Load directory traversal payloads list
pub fn load_directory_traversal_payloads() -> FortiCoreResult<Vec<String>> {
    let data: serde_json::Value = load_resource("payloads.json")?;
    let payloads = data["directory_traversal_payloads"]
        .as_array()
        .ok_or_else(|| {
            FortiCoreError::ResourceError(
                "Failed to find directory_traversal_payloads in payloads.json".to_string(),
            )
        })?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    Ok(payloads)
}

/// Load LFI payloads list
pub fn load_lfi_payloads() -> FortiCoreResult<Vec<String>> {
    let data: serde_json::Value = load_resource("payloads.json")?;
    let payloads = data["lfi_payloads"]
        .as_array()
        .ok_or_else(|| {
            FortiCoreError::ResourceError(
                "Failed to find lfi_payloads in payloads.json".to_string(),
            )
        })?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    Ok(payloads)
}

/// Load open redirect payloads list
pub fn load_open_redirect_payloads() -> FortiCoreResult<Vec<String>> {
    let data: serde_json::Value = load_resource("payloads.json")?;
    let payloads = data["open_redirect_payloads"]
        .as_array()
        .ok_or_else(|| {
            FortiCoreError::ResourceError(
                "Failed to find open_redirect_payloads in payloads.json".to_string(),
            )
        })?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    Ok(payloads)
}

/// Load important security headers list
pub fn load_security_headers() -> FortiCoreResult<Vec<String>> {
    let data: serde_json::Value = load_resource("payloads.json")?;
    let headers = data["security_headers"]["important_headers"]
        .as_array()
        .ok_or_else(|| {
            FortiCoreError::ResourceError(
                "Failed to find security_headers.important_headers in payloads.json".to_string(),
            )
        })?
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    Ok(headers)
}

/// Save a new custom resource file
pub fn save_custom_resource(filename: &str, content: &Value) -> FortiCoreResult<()> {
    let path = get_resource_path(filename);
    let json_string = serde_json::to_string_pretty(content).map_err(|e| {
        FortiCoreError::ResourceError(format!("Failed to serialize resource data: {}", e))
    })?;

    fs::write(&path, json_string).map_err(|e| {
        FortiCoreError::ResourceError(format!("Failed to write resource file {}: {}", path, e))
    })?;

    // Update cache
    if let Some(cache) = RESOURCE_CACHE.get() {
        let mut new_cache = cache.clone();
        new_cache.insert(filename.to_string(), content.clone());
        let _ = RESOURCE_CACHE.set(new_cache);
    }

    Ok(())
}

/// Generate a custom resource file from a template
pub fn generate_resource_template(filename: &str) -> FortiCoreResult<()> {
    let template = match filename {
        "custom_subdomains.json" => serde_json::json!({
            "custom_subdomains": [
                "custom1",
                "custom2",
                "custom3"
            ]
        }),
        "custom_payloads.json" => serde_json::json!({
            "custom_xss_payloads": [
                "<custom>alert('XSS')</custom>"
            ],
            "custom_sql_injection_payloads": [
                "' OR 'custom'='custom"
            ]
        }),
        _ => {
            return Err(FortiCoreError::ResourceError(format!(
                "Unknown template type: {}",
                filename
            )))
        }
    };

    save_custom_resource(filename, &template)
}

// Check if all required resource files exist, create them if they don't
pub fn ensure_resources_exist() -> FortiCoreResult<()> {
    let required_files = vec!["subdomains.json", "payloads.json"];

    for file in required_files {
        let path = get_resource_path(file);
        if !Path::new(&path).exists() {
            match file {
                "subdomains.json" => {
                    let subdomains = serde_json::json!({
                        "common_subdomains": [
                            "www", "mail", "ftp" // Add more default values as needed
                        ]
                    });
                    save_custom_resource(file, &subdomains)?;
                }
                "payloads.json" => {
                    let payloads = serde_json::json!({
                        "xss_payloads": [
                            "<script>alert('XSS')</script>" // Add more default values as needed
                        ],
                        "sql_injection_payloads": [
                            "' OR '1'='1" // Add more default values as needed
                        ],
                        "directory_traversal_payloads": [
                            "../../../etc/passwd" // Add more default values as needed
                        ],
                        "lfi_payloads": [
                            "/etc/passwd" // Add more default values as needed
                        ],
                        "open_redirect_payloads": [
                            "https://evil.com" // Add more default values as needed
                        ],
                        "security_headers": {
                            "important_headers": [
                                "Content-Security-Policy" // Add more default values as needed
                            ]
                        }
                    });
                    save_custom_resource(file, &payloads)?;
                }
                _ => {}
            }
        }
    }

    Ok(())
}
