use crate::scanners::{Severity, Vulnerability};
use crate::utils::error::FortiCoreResult;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde_json::{json, Value};
use regex::Regex;
use std::collections::HashSet;

/// Checks for JWT token vulnerabilities
pub async fn check_jwt_vulnerabilities(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Common API paths that might use JWT tokens
    let api_paths = [
        "/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/", "/rest/", 
        "/graphql", "/auth/", "/oauth/", "/token"
    ];
    
    // First, try to find JWT tokens in the response
    for path in &api_paths {
        let url = if base_url.ends_with('/') {
            format!("{}{}", base_url, path.trim_start_matches('/'))
        } else {
            format!("{}{}", base_url, path)
        };
        
        let response = match client.get(&url).send().await {
            Ok(resp) => resp,
            Err(_) => continue, // Skip to next URL if this one fails
        };
        
        // Check response headers for JWT
        let mut jwt_token = None;
        
        // Common header names that might contain JWTs
        for header_name in &["authorization", "x-access-token", "jwt", "token", "x-token"] {
            if let Some(header_value) = response.headers().get(*header_name) {
                if let Ok(value_str) = header_value.to_str() {
                    // Extract token if it's prefixed with "Bearer "
                    let token = if value_str.starts_with("Bearer ") {
                        value_str[7..].to_string()
                    } else {
                        value_str.to_string()
                    };
                    
                    // Check if it looks like a JWT (xxx.yyy.zzz format)
                    if is_jwt_format(&token) {
                        jwt_token = Some(token);
                        break;
                    }
                }
            }
        }
        
        // If no JWT found in headers, check response body for tokens
        if jwt_token.is_none() {
            match response.text().await {
                Ok(body) => {
                    // Simple pattern to find potential JWTs in JSON responses
                    let re = Regex::new(r#"["']?(?:token|jwt|accessToken|access_token|id_token)["']?\s*[:=]\s*["']([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']"#).unwrap();
                    
                    if let Some(caps) = re.captures(&body) {
                        if let Some(matched) = caps.get(1) {
                            let token = matched.as_str().to_string();
                            if is_jwt_format(&token) {
                                jwt_token = Some(token);
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        
        // Analyze JWT token if found
        if let Some(token) = jwt_token {
            let jwt_parts: Vec<&str> = token.split('.').collect();
            
            if jwt_parts.len() == 3 {
                let header_base64 = jwt_parts[0];
                let decoded_header = decode_jwt_header(header_base64);
                
                let (has_vulnerability, issue) = analyze_jwt_security(&decoded_header, jwt_parts);
                
                if has_vulnerability {
                    let vuln = Vulnerability {
                        id: "WEB-107".to_string(),
                        name: "JWT Security Issues".to_string(),
                        description: format!("A JWT token was found with security issues: {}", issue),
                        severity: Severity::High,
                        location: url.clone(),
                        details: json!({
                            "issue": issue,
                            "token_header": decoded_header,
                            "path": path
                        }),
                        exploitable: true,
                    };
                    
                    return Ok(Some(vuln));
                }
            }
        }
    }
    
    Ok(None)
}

/// Checks if a string matches the JWT format (xxx.yyy.zzz)
fn is_jwt_format(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    
    // Check that each part only contains valid base64url characters
    for part in &parts[0..2] { // Header and payload should be valid base64
        if !part.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return false;
        }
    }
    
    // Try to decode the header to make sure it's actually a JWT
    if let Err(_) = decode_jwt_part(parts[0]) {
        return false;
    }
    
    true
}

/// Decodes a base64url-encoded JWT part
fn decode_jwt_part(part: &str) -> Result<String, String> {
    // Ensure proper padding for base64 decoding
    let mut padded = part.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    
    // Convert from base64url to base64
    let base64 = padded
        .replace('-', "+")
        .replace('_', "/");
    
    // Decode base64
    match STANDARD.decode(base64) {
        Ok(decoded) => match String::from_utf8(decoded) {
            Ok(string) => Ok(string),
            Err(_) => Err("Failed to convert to UTF-8".to_string()),
        },
        Err(_) => Err("Failed to decode base64".to_string()),
    }
}

/// Decodes the JWT header
fn decode_jwt_header(header_base64: &str) -> String {
    match decode_jwt_part(header_base64) {
        Ok(decoded) => decoded,
        Err(_) => "Invalid JWT header".to_string(), // Return something to prevent panics
    }
}

/// Analyzes a JWT token for security issues
fn analyze_jwt_security(decoded_header: &str, jwt_parts: Vec<&str>) -> (bool, String) {
    let header_json: Value = match serde_json::from_str(decoded_header) {
        Ok(json) => json,
        Err(_) => return (true, "Invalid JWT header format".to_string()),
    };
    
    // Check for 'none' algorithm
    if let Some(alg) = header_json.get("alg") {
        if let Some(alg_str) = alg.as_str() {
            if alg_str.to_lowercase() == "none" {
                return (true, "JWT uses 'none' algorithm which bypasses signature verification".to_string());
            }
            
            // Check for weak algorithms
            match alg_str {
                "HS256" => {
                    // Check for common weak secrets by trying to verify with them
                    // This is a simplified version - in a real implementation we would try to verify
                    return (false, String::new()); // Not a vulnerability, just noting the algorithm
                }
                "RS256" | "ES256" | "PS256" => {
                    // These are generally secure algorithms unless implementation is flawed
                    return (false, String::new());
                }
                _ => {
                    // Other algorithms might be custom or deprecated
                    if alg_str.starts_with("HS") && alg_str != "HS384" && alg_str != "HS512" {
                        return (true, format!("JWT uses potentially weak algorithm: {}", alg_str));
                    }
                }
            }
        }
    } else {
        return (true, "JWT header missing 'alg' field".to_string());
    }
    
    // No vulnerabilities found
    (false, String::new())
} 