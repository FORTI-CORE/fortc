use crate::resources;
use crate::scanners::{Severity, Vulnerability};
use crate::utils::error::FortiCoreResult;
use regex::Regex;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::timeout;
use urlencoding;

/// Checks HTTP response headers for security issues
pub async fn check_headers(client: &Client, url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    let response = client.get(url).send().await?;
    let headers = response.headers();
    let mut missing_headers = Vec::new();
    let mut security_issues = Vec::new();

    // Check for missing security headers
    let important_headers = resources::load_security_headers()?;

    for header in &important_headers {
        if !headers.contains_key(header) {
            missing_headers.push(header.clone());
        }
    }

    // Check for potentially insecure headers
    if let Some(server) = headers.get("Server") {
        if let Ok(server_value) = server.to_str() {
            if server_value.contains("/") || server_value.contains(".") {
                security_issues.push(format!("Server header discloses version: {}", server_value));
            }
        }
    }

    if let Some(powered_by) = headers.get("X-Powered-By") {
        if let Ok(powered_by_value) = powered_by.to_str() {
            security_issues.push(format!(
                "X-Powered-By header discloses technology: {}",
                powered_by_value
            ));
        }
    }

    if !missing_headers.is_empty() || !security_issues.is_empty() {
        let mut details = json!({});
        if !missing_headers.is_empty() {
            details["missing_headers"] = json!(missing_headers);
        }
        if !security_issues.is_empty() {
            details["security_issues"] = json!(security_issues);
        }

        let severity = if !security_issues.is_empty() {
            Severity::Medium
        } else {
            Severity::Low
        };

        let vuln = Vulnerability {
            id: "WEB-100".to_string(),
            name: "Insecure HTTP Headers".to_string(),
            description: "The server is missing some recommended security headers or includes potentially insecure headers.".to_string(),
            severity,
            location: url.to_string(),
            details,
            exploitable: false,
        };

        return Ok(Some(vuln));
    }

    Ok(None)
}

/// Checks for sensitive information in robots.txt
pub async fn check_robots_txt(
    client: &Client,
    url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    let robots_url = if url.ends_with('/') {
        format!("{}robots.txt", url)
    } else {
        format!("{}/robots.txt", url)
    };

    let response = match client.get(&robots_url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                resp
            } else {
                return Ok(None); // No robots.txt or not accessible
            }
        }
        Err(_) => return Ok(None), // Error accessing robots.txt
    };

    let content = response.text().await?;
    let interesting_paths = find_interesting_paths_in_robots(&content);

    if !interesting_paths.is_empty() {
        let vuln = Vulnerability {
            id: "WEB-101".to_string(),
            name: "Sensitive Information in robots.txt".to_string(),
            description:
                "robots.txt contains references to potentially sensitive directories or files."
                    .to_string(),
            severity: Severity::Low,
            location: robots_url,
            details: json!({ "interesting_paths": interesting_paths }),
            exploitable: false,
        };

        return Ok(Some(vuln));
    }

    Ok(None)
}

/// Finds potentially interesting paths mentioned in robots.txt
fn find_interesting_paths_in_robots(content: &str) -> Vec<String> {
    let interesting_keywords = [
        "admin",
        "backup",
        "config",
        "db",
        "debug",
        "login",
        "test",
        "temp",
        "api",
        "console",
        "dashboard",
        "secret",
        "database",
        "user",
        "password",
        "key",
        "private",
        "wp-admin",
        "wp-content",
        "phpmyadmin",
        "cpanel",
        "administrator",
    ];

    let mut interesting_paths = Vec::new();

    // Look for Disallow or Allow directives
    let re = Regex::new(r"(?i)(Disallow|Allow):\s*([^\s#]+)").unwrap();

    for cap in re.captures_iter(content) {
        let path = cap.get(2).unwrap().as_str();

        // Check if the path contains any of the interesting keywords
        if interesting_keywords
            .iter()
            .any(|&keyword| path.to_lowercase().contains(keyword))
        {
            interesting_paths.push(path.to_string());
        }
    }

    interesting_paths
}

/// Checks CORS configuration for security issues
pub async fn check_cors(client: &Client, url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    // Create a custom Origin header to test CORS
    let test_origin = "https://evil-site.example.com";

    let response = client.get(url).header("Origin", test_origin).send().await?;

    let headers = response.headers();

    // Check for potential CORS misconfiguration
    if let Some(acao) = headers.get("Access-Control-Allow-Origin") {
        if let Ok(acao_value) = acao.to_str() {
            if acao_value == "*" || acao_value == test_origin {
                let details = json!({
                    "acao_value": acao_value,
                    "test_origin": test_origin,
                });

                let vuln = Vulnerability {
                    id: "WEB-003".to_string(),
                    name: "CORS Misconfiguration".to_string(),
                    description: "The server has a permissive CORS policy that could allow cross-origin requests from arbitrary domains.".to_string(),
                    severity: Severity::Medium,
                    location: url.to_string(),
                    details,
                    exploitable: true,
                };

                return Ok(Some(vuln));
            }
        }
    }

    Ok(None)
}

/// Checks for server version disclosure in headers
pub async fn check_server_version_disclosure(
    client: &Client,
    url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    let response = client.get(url).send().await?;
    let headers = response.headers();

    let mut version_disclosures = Vec::new();

    // Check Server header
    if let Some(server) = headers.get("Server") {
        if let Ok(server_value) = server.to_str() {
            // Look for version numbers, typically following a / or space
            if Regex::new(r"\d+\.\d+").unwrap().is_match(server_value) {
                version_disclosures.push(format!("Server: {}", server_value));
            }
        }
    }

    // Check X-Powered-By header
    if let Some(powered_by) = headers.get("X-Powered-By") {
        if let Ok(powered_by_value) = powered_by.to_str() {
            // Look for version numbers
            if Regex::new(r"\d+\.\d+").unwrap().is_match(powered_by_value) {
                version_disclosures.push(format!("X-Powered-By: {}", powered_by_value));
            }
        }
    }

    if !version_disclosures.is_empty() {
        let vuln = Vulnerability {
            id: "WEB-102".to_string(),
            name: "Server Version Disclosure".to_string(),
            description: "The server is revealing version information in HTTP headers.".to_string(),
            severity: Severity::Low,
            location: url.to_string(),
            details: json!({ "disclosures": version_disclosures }),
            exploitable: false,
        };

        return Ok(Some(vuln));
    }

    Ok(None)
}

/// Checks for insecure cookie settings
pub async fn check_insecure_cookies(
    client: &Client,
    url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Only check HTTPS URLs for secure flag
    let is_https = url.starts_with("https://");

    let response = client.get(url).send().await?;

    // Get cookies from the Set-Cookie header since reqwest::Response doesn't have a cookies() method
    let mut insecure_cookies = Vec::new();

    for cookie_header in response.headers().get_all("set-cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            let cookie_name = cookie_str
                .split(';')
                .next()
                .and_then(|s| s.split('=').next())
                .unwrap_or("unknown")
                .trim();

            let mut issues = Vec::new();

            // Check for Secure flag on HTTPS sites
            if is_https && !cookie_str.to_lowercase().contains("secure") {
                issues.push("Missing Secure flag".to_string());
            }

            // Check for HttpOnly flag
            if !cookie_str.to_lowercase().contains("httponly") {
                issues.push("Missing HttpOnly flag".to_string());
            }

            // Check for SameSite attribute
            if !cookie_str.to_lowercase().contains("samesite") {
                issues.push("Missing SameSite attribute".to_string());
            }

            if !issues.is_empty() {
                insecure_cookies.push(json!({
                    "name": cookie_name,
                    "issues": issues
                }));
            }
        }
    }

    if !insecure_cookies.is_empty() {
        let vuln = Vulnerability {
            id: "WEB-103".to_string(),
            name: "Insecure Cookies".to_string(),
            description: "The server sets cookies without proper security attributes.".to_string(),
            severity: Severity::Medium,
            location: url.to_string(),
            details: json!({ "cookies": insecure_cookies }),
            exploitable: false,
        };

        return Ok(Some(vuln));
    }

    Ok(None)
}

/// Checks for insecure file upload vulnerabilities
pub async fn check_insecure_file_upload(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Common paths that might contain file upload forms
    let upload_paths = [
        "/upload",
        "/file-upload",
        "/upload.php",
        "/fileupload",
        "/admin/upload",
        "/wp-admin/upload.php",
        "/admin/filemanager",
        "/upload-file",
        "/files/upload",
        "/media/upload",
    ];

    for path in &upload_paths {
        let url = if base_url.ends_with('/') {
            format!("{}{}", base_url, path.trim_start_matches('/'))
        } else {
            format!("{}{}", base_url, path)
        };

        let response = match client.get(&url).send().await {
            Ok(resp) => resp,
            Err(_) => continue, // Skip to next URL if this one fails
        };

        // Look for file upload forms or handlers
        let content = match response.text().await {
            Ok(text) => text,
            Err(_) => continue,
        };

        // Check for file upload forms
        if content.contains("multipart/form-data")
            && (content.contains("type=\"file\"") || content.contains("type='file'"))
        {
            let vuln = Vulnerability {
                id: "WEB-111".to_string(),
                name: "Potential File Upload Endpoint".to_string(),
                description: "A file upload form was detected that could potentially allow for malicious file uploads.".to_string(),
                severity: Severity::Info,
                location: url,
                details: json!({ "path": path }),
                exploitable: false,
            };

            return Ok(Some(vuln));
        }
    }

    Ok(None)
}

/// Checks for cross-site scripting (XSS) vulnerabilities
pub async fn check_xss_enhanced(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    // Load XSS payloads from resources
    let xss_payloads = resources::load_xss_payloads()?;

    // Find potential input points
    let input_points = find_input_points(client, base_url).await?;

    for input_point in input_points {
        for payload in &xss_payloads {
            // Test the payload on the input point
            if let Some(vuln) = test_xss_payload(client, &input_point, payload).await? {
                vulnerabilities.push(vuln);
                // No need to test more payloads on this input point once we've found a vulnerability
                break;
            }
        }
    }

    Ok(vulnerabilities)
}

/// Checks for SQL injection vulnerabilities
pub async fn check_sql_injection_enhanced(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Load SQL injection payloads from resources
    let sql_payloads = resources::load_sql_injection_payloads()?;

    // ... rest of function implementation ...

    // This is just a placeholder - real implementation would use the payloads
    // to test for SQL injection vulnerabilities
    Ok(None)
}

/// Checks for directory traversal vulnerabilities
pub async fn check_directory_traversal(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Load directory traversal payloads from resources
    let traversal_payloads = resources::load_directory_traversal_payloads()?;

    // ... rest of function implementation ...

    // This is just a placeholder - real implementation would use the payloads
    // to test for directory traversal vulnerabilities
    Ok(None)
}

/// Checks for Local File Inclusion vulnerabilities
pub async fn check_lfi(client: &Client, base_url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    // Load LFI payloads from resources
    let lfi_payloads = resources::load_lfi_payloads()?;

    // ... rest of function implementation ...

    // This is just a placeholder - real implementation would use the payloads
    // to test for LFI vulnerabilities
    Ok(None)
}

/// Checks for open redirect vulnerabilities
pub async fn check_open_redirect(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Load open redirect payloads from resources
    let redirect_payloads = resources::load_open_redirect_payloads()?;

    // ... rest of function implementation ...

    // This is just a placeholder - real implementation would use the payloads
    // to test for open redirect vulnerabilities
    Ok(None)
}

/// Find potential input points in a webpage
async fn find_input_points(client: &Client, base_url: &str) -> FortiCoreResult<Vec<String>> {
    // Common URL parameters to test
    let test_params = [
        "q", "search", "id", "query", "page", "keyword", "keywords", "term", "terms", "s", "input",
        "name", "user", "username", "email", "message", "comment",
    ];

    let mut input_points = Vec::new();

    // Add URL parameters as potential input points
    for param in &test_params {
        let url = if base_url.contains('?') {
            format!("{}&{}=test", base_url, param)
        } else {
            format!("{}?{}=test", base_url, param)
        };
        input_points.push(url);
    }

    // In a real implementation, we would also look for forms and other input elements
    // by parsing the HTML of the page

    Ok(input_points)
}

/// Test a specific XSS payload against an input point
async fn test_xss_payload(
    client: &Client,
    url: &str,
    payload: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Replace the "test" value with our actual payload
    let test_url = url.replace("=test", &format!("={}", urlencoding::encode(payload)));

    let response = match client.get(&test_url).send().await {
        Ok(resp) => resp,
        Err(_) => return Ok(None),
    };

    let content = match response.text().await {
        Ok(text) => text,
        Err(_) => return Ok(None),
    };

    // Check if payload is reflected in response
    if content.contains(payload) {
        // Extract parameter name from URL
        let param_name = url
            .split('?')
            .nth(1)
            .and_then(|q| q.split('&').find(|p| p.contains("=test")))
            .and_then(|p| p.split('=').nth(0))
            .unwrap_or("unknown");

        let vuln = Vulnerability {
            id: "WEB-001".to_string(),
            name: "Cross-Site Scripting (XSS)".to_string(),
            description: format!(
                "URL parameter '{}' is vulnerable to XSS. Payload is reflected in the response without proper encoding.", 
                param_name
            ),
            severity: Severity::High,
            location: test_url.clone(),
            details: json!({
                "parameter": param_name,
                "payload": payload,
                "type": "Reflected XSS"
            }),
            exploitable: true,
        };

        return Ok(Some(vuln));
    }

    Ok(None)
}
