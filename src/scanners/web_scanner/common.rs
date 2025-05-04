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
    let important_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
    ];

    for &header in &important_headers {
        if !headers.contains_key(header) {
            missing_headers.push(header);
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

/// Check for potential XSS vulnerabilities
pub async fn check_xss_enhanced(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    // Common URL parameters to test
    let test_params = [
        "q", "search", "id", "query", "page", "keyword", "keywords", "term", "terms", "s", "input",
        "name", "user", "username", "email", "message", "comment",
    ];

    let test_payloads = [
        r#"<script>alert("XSS")</script>"#,
        r#"<img src=x onerror=alert("XSS")>"#,
        r#"'"><img src=x onerror=alert("XSS")>"#,
    ];

    // Test reflection in URL parameters
    for param in &test_params {
        for payload in &test_payloads {
            let url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
            };

            let response = match client.get(&url).send().await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            let content = match response.text().await {
                Ok(text) => text,
                Err(_) => continue,
            };

            // Check if payload is reflected in response
            if content.contains(payload) {
                let vuln = Vulnerability {
                    id: "WEB-001".to_string(),
                    name: "Cross-Site Scripting (XSS)".to_string(),
                    description: format!("URL parameter '{}' is vulnerable to XSS. Payload is reflected in the response without proper encoding.", param),
                    severity: Severity::High,
                    location: url.clone(),
                    details: json!({
                        "parameter": param,
                        "payload": payload,
                        "type": "Reflected XSS"
                    }),
                    exploitable: true,
                };

                vulnerabilities.push(vuln);
                break; // Move to next parameter once vulnerability is found
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
    // Common URL parameters to test
    let test_params = [
        "id", "user_id", "item", "page_id", "pid", "cat", "category", "product", "article", "post",
        "news", "item_id", "uid",
    ];

    let sql_payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "1 OR 1=1",
        "' OR '1'='1' --",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "1)) OR ((1=1",
    ];

    // SQL error patterns that might indicate SQL injection
    let error_patterns = [
        "SQL syntax",
        "mysql_fetch_array",
        "mysqli_fetch_array",
        "ORA-",
        "Oracle error",
        "Microsoft SQL Native Client",
        "syntax error",
        "unclosed quotation mark",
        "mysql_fetch",
        "SQLite3::",
        "PG::SyntaxError",
        "PostgreSQL",
    ];

    for param in &test_params {
        for payload in &sql_payloads {
            let url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
            };

            let response = match client.get(&url).send().await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            let content = match response.text().await {
                Ok(text) => text,
                Err(_) => continue,
            };

            // Check for SQL error patterns
            for pattern in &error_patterns {
                if content.contains(pattern) {
                    let vuln = Vulnerability {
                        id: "WEB-002".to_string(),
                        name: "SQL Injection".to_string(),
                        description: format!("URL parameter '{}' appears to be vulnerable to SQL injection. SQL error messages are being returned in the response.", param),
                        severity: Severity::Critical,
                        location: url.clone(),
                        details: json!({
                            "parameter": param,
                            "payload": payload,
                            "error_pattern": pattern
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

/// Checks for directory traversal vulnerabilities
pub async fn check_directory_traversal(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    let test_params = [
        "path",
        "file",
        "page",
        "template",
        "lang",
        "doc",
        "include",
        "dir",
        "folder",
        "document",
        "root",
        "filename",
        "path_to_file",
    ];

    let traversal_payloads = [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
    ];

    // Patterns that might indicate successful traversal
    let unix_patterns = ["root:x:", "bin:", "daemon:", "nobody:", "/home/"];
    let windows_patterns = [
        "[fonts]",
        "[extensions]",
        "[files]",
        "for 16-bit app support",
    ];

    for param in &test_params {
        for payload in &traversal_payloads {
            let url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
            };

            let response = match client.get(&url).send().await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            let content = match response.text().await {
                Ok(text) => text,
                Err(_) => continue,
            };

            // Check for signs of successful traversal
            let patterns = if payload.contains("etc/passwd") {
                &unix_patterns[..]
            } else {
                &windows_patterns[..]
            };

            for pattern in patterns {
                if content.contains(pattern) {
                    let vuln = Vulnerability {
                        id: "WEB-104".to_string(),
                        name: "Directory Traversal".to_string(),
                        description: format!("URL parameter '{}' appears to be vulnerable to directory traversal/path traversal attacks.", param),
                        severity: Severity::High,
                        location: url.clone(),
                        details: json!({
                            "parameter": param,
                            "payload": payload,
                            "matched_pattern": pattern
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

/// Checks for Local File Inclusion vulnerabilities
pub async fn check_lfi(client: &Client, base_url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    let test_params = [
        "include", "file", "document", "page", "template", "path", "language", "module", "theme",
        "view", "content",
    ];

    let lfi_payloads = [
        "etc/passwd",
        "/etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "windows/win.ini",
        "/windows/win.ini",
        "../../../windows/win.ini",
        "../../../../windows/win.ini",
    ];

    // Patterns that might indicate successful LFI
    let unix_patterns = ["root:x:", "bin:", "daemon:", "nobody:", "/home/"];
    let windows_patterns = [
        "[fonts]",
        "[extensions]",
        "[files]",
        "for 16-bit app support",
    ];

    for param in &test_params {
        for payload in &lfi_payloads {
            let url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
            };

            let response = match client.get(&url).send().await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            let content = match response.text().await {
                Ok(text) => text,
                Err(_) => continue,
            };

            // Check for signs of successful LFI
            let patterns = if payload.contains("etc/passwd") {
                &unix_patterns[..]
            } else {
                &windows_patterns[..]
            };

            for pattern in patterns {
                if content.contains(pattern) {
                    let vuln = Vulnerability {
                        id: "WEB-105".to_string(),
                        name: "Local File Inclusion (LFI)".to_string(),
                        description: format!(
                            "URL parameter '{}' appears to be vulnerable to Local File Inclusion.",
                            param
                        ),
                        severity: Severity::Critical,
                        location: url.clone(),
                        details: json!({
                            "parameter": param,
                            "payload": payload,
                            "matched_pattern": pattern
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

/// Checks for open redirect vulnerabilities
pub async fn check_open_redirect(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    let test_params = [
        "url",
        "redirect",
        "next",
        "redirect_to",
        "return",
        "return_url",
        "goto",
        "returnUrl",
        "return_to",
        "next_page",
        "redir",
        "r",
    ];

    let redirect_payloads = [
        "https://example.com",
        "//example.com",
        "https%3A%2F%2Fexample.com",
        "%2F%2Fexample.com",
    ];

    for param in &test_params {
        for payload in &redirect_payloads {
            let url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, param, payload)
            } else {
                format!("{}?{}={}", base_url, param, payload)
            };

            // Don't follow redirects
            let custom_client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?;

            let response = match custom_client.get(&url).send().await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            // Check if the response is a redirect to our payload URL
            if response.status().is_redirection() {
                if let Some(location) = response.headers().get("location") {
                    if let Ok(location_str) = location.to_str() {
                        if location_str.contains("example.com") {
                            let vuln = Vulnerability {
                                id: "WEB-106".to_string(),
                                name: "Open Redirect".to_string(),
                                description: format!("URL parameter '{}' appears to be vulnerable to open redirect attacks.", param),
                                severity: Severity::Medium,
                                location: url.clone(),
                                details: json!({
                                    "parameter": param,
                                    "payload": payload,
                                    "redirect_url": location_str
                                }),
                                exploitable: true,
                            };

                            return Ok(Some(vuln));
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}
