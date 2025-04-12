use crate::scanners::{Severity, Vulnerability};
use crate::utils::{error::FortiCoreResult, FortiCoreError};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use serde_json::json;
use std::path::Path;

pub async fn scan(target: &str, output_path: Option<&Path>, verbose: bool) -> FortiCoreResult<()> {
    if verbose {
        println!("Starting web scan on target: {}", target);
    }

    let target_url = normalize_url(target);
    let client = create_client()?;

    let mut vulnerabilities = Vec::new();

    // Basic information gathering
    if verbose {
        println!("Gathering basic information about the web server...");
    }

    // Check for HTTP response headers
    let headers = check_headers(&client, &target_url).await?;
    if let Some(vuln) = headers {
        vulnerabilities.push(vuln);
    }

    // Check for robots.txt
    if verbose {
        println!("Checking for robots.txt...");
    }
    let robots = check_robots_txt(&client, &target_url).await?;
    if let Some(vuln) = robots {
        vulnerabilities.push(vuln);
    }

    // Check for server version
    if verbose {
        println!("Checking for server version disclosure...");
    }
    let server_version = check_server_version_disclosure(&client, &target_url).await?;
    if let Some(vuln) = server_version {
        vulnerabilities.push(vuln);
    }

    // Check for common vulnerabilities
    if verbose {
        println!("Checking for common web vulnerabilities...");
    }

    // CORS misconfiguration
    let cors = check_cors(&client, &target_url).await?;
    if let Some(vuln) = cors {
        vulnerabilities.push(vuln);
    }

    // Check for insecure cookies
    if verbose {
        println!("Checking for insecure cookies...");
    }
    let cookies = check_insecure_cookies(&client, &target_url).await?;
    if let Some(vuln) = cookies {
        vulnerabilities.push(vuln);
    }

    // XSS reflection test (enhanced)
    if verbose {
        println!("Checking for XSS vulnerabilities...");
    }
    let xss = check_xss_enhanced(&client, &target_url).await?;
    for vuln in xss {
        vulnerabilities.push(vuln);
    }

    // SQL Injection test (enhanced)
    if verbose {
        println!("Checking for SQL injection vulnerabilities...");
    }
    let sqli = check_sql_injection_enhanced(&client, &target_url).await?;
    if let Some(vuln) = sqli {
        vulnerabilities.push(vuln);
    }

    // Directory traversal test
    if verbose {
        println!("Checking for directory traversal vulnerabilities...");
    }
    let dir_traversal = check_directory_traversal(&client, &target_url).await?;
    if let Some(vuln) = dir_traversal {
        vulnerabilities.push(vuln);
    }

    // Local file inclusion (LFI) test
    if verbose {
        println!("Checking for local file inclusion vulnerabilities...");
    }
    let lfi = check_lfi(&client, &target_url).await?;
    if let Some(vuln) = lfi {
        vulnerabilities.push(vuln);
    }

    // Open redirect test
    if verbose {
        println!("Checking for open redirect vulnerabilities...");
    }
    let open_redirect = check_open_redirect(&client, &target_url).await?;
    if let Some(vuln) = open_redirect {
        vulnerabilities.push(vuln);
    }

    // JWT vulnerability check
    if verbose {
        println!("Checking for JWT token vulnerabilities...");
    }
    let jwt_vuln = check_jwt_vulnerabilities(&client, &target_url).await?;
    if let Some(vuln) = jwt_vuln {
        vulnerabilities.push(vuln);
    }

    // Insecure file upload check
    if verbose {
        println!("Checking for file upload vulnerabilities...");
    }
    let file_upload = check_insecure_file_upload(&client, &target_url).await?;
    if let Some(vuln) = file_upload {
        vulnerabilities.push(vuln);
    }

    if verbose {
        println!(
            "Web scan completed. Found {} vulnerabilities.",
            vulnerabilities.len()
        );
        for vuln in &vulnerabilities {
            println!(
                "- {} ({:?}): {}",
                vuln.name, vuln.severity, vuln.description
            );
        }
    }

    // Save results if output path is provided
    if let Some(path) = output_path {
        save_scan_results(&vulnerabilities, path)?;
    }

    Ok(())
}

fn normalize_url(url: &str) -> String {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("http://{}", url)
    } else {
        url.to_string()
    }
}

fn create_client() -> FortiCoreResult<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("FortiCore/0.1.0"));

    let client = Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            FortiCoreError::NetworkError(format!("Failed to create HTTP client: {}", e))
        })?;

    Ok(client)
}

async fn check_headers(client: &Client, url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    let resp = client.get(url).send().await.map_err(|e| {
        FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", url, e))
    })?;

    let headers = resp.headers();
    let mut issues = Vec::new();

    // Check for security headers
    if !headers.contains_key("X-XSS-Protection") {
        issues.push("Missing X-XSS-Protection header");
    }

    if !headers.contains_key("X-Content-Type-Options") {
        issues.push("Missing X-Content-Type-Options header");
    }

    if !headers.contains_key("Content-Security-Policy") {
        issues.push("Missing Content-Security-Policy header");
    }

    if !headers.contains_key("Strict-Transport-Security") && url.starts_with("https") {
        issues.push("Missing Strict-Transport-Security header");
    }

    if issues.is_empty() {
        return Ok(None);
    }

    let server_info = if let Some(server) = headers.get("Server") {
        server.to_str().unwrap_or("Unknown").to_string()
    } else {
        "Unknown".to_string()
    };

    let vuln = Vulnerability {
        id: "WEB-001".to_string(),
        name: "Missing Security Headers".to_string(),
        description: format!(
            "The server is missing important security headers: {}",
            issues.join(", ")
        ),
        severity: Severity::Medium,
        location: url.to_string(),
        details: json!({
            "server": server_info,
            "missing_headers": issues,
        }),
        exploitable: false,
    };

    Ok(Some(vuln))
}

async fn check_robots_txt(client: &Client, url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    let robots_url = format!("{}/robots.txt", url.trim_end_matches('/'));

    let resp = client.get(&robots_url).send().await.map_err(|e| {
        FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", robots_url, e))
    })?;

    if !resp.status().is_success() {
        return Ok(None); // No robots.txt found, not a vulnerability
    }

    let body = resp
        .text()
        .await
        .map_err(|e| FortiCoreError::NetworkError(format!("Failed to read response: {}", e)))?;

    // Check if robots.txt contains sensitive directories
    let sensitive_patterns = [
        "admin",
        "login",
        "wp-admin",
        "administrator",
        "phpmyadmin",
        "config",
        "backup",
        "db",
        "database",
        "secret",
        "private",
    ];

    let mut found_sensitive = Vec::new();

    for pattern in &sensitive_patterns {
        if body.to_lowercase().contains(pattern) {
            found_sensitive.push(*pattern);
        }
    }

    if found_sensitive.is_empty() {
        return Ok(None);
    }

    let vuln = Vulnerability {
        id: "WEB-002".to_string(),
        name: "Sensitive Information in robots.txt".to_string(),
        description: format!(
            "The robots.txt file contains references to potentially sensitive directories: {}",
            found_sensitive.join(", ")
        ),
        severity: Severity::Low,
        location: robots_url,
        details: json!({
            "sensitive_directories": found_sensitive,
            "robots_txt_content": body,
        }),
        exploitable: false,
    };

    Ok(Some(vuln))
}

async fn check_cors(client: &Client, url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    let resp = client
        .get(url)
        .header("Origin", "https://forticore-scan.example.com")
        .send()
        .await
        .map_err(|e| {
            FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", url, e))
        })?;

    let headers = resp.headers();

    if let Some(acao) = headers.get("Access-Control-Allow-Origin") {
        let value = acao.to_str().unwrap_or("");

        if value == "*" || value == "https://forticore-scan.example.com" {
            let vuln = Vulnerability {
                id: "WEB-003".to_string(),
                name: "CORS Misconfiguration".to_string(),
                description: if value == "*" {
                    "The server allows cross-origin requests from any domain".to_string()
                } else {
                    "The server allows cross-origin requests from arbitrary domains".to_string()
                },
                severity: Severity::Medium,
                location: url.to_string(),
                details: json!({
                    "header": "Access-Control-Allow-Origin",
                    "value": value,
                }),
                exploitable: true,
            };

            return Ok(Some(vuln));
        }
    }

    Ok(None)
}

async fn check_server_version_disclosure(
    client: &Client,
    url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    let resp = client.get(url).send().await.map_err(|e| {
        FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", url, e))
    })?;

    let headers = resp.headers();

    if let Some(server) = headers.get("Server") {
        let server_value = server.to_str().unwrap_or("Unknown");

        // Check if server header contains version information
        if server_value.contains("/") && server_value.matches(char::is_numeric).count() > 0 {
            let vuln = Vulnerability {
                id: "WEB-006".to_string(),
                name: "Server Version Disclosure".to_string(),
                description:
                    "The server discloses detailed version information which could aid attackers"
                        .to_string(),
                severity: Severity::Low,
                location: url.to_string(),
                details: json!({
                    "server": server_value,
                    "recommendation": "Configure the server to hide version information in HTTP headers"
                }),
                exploitable: false,
            };

            return Ok(Some(vuln));
        }
    }

    Ok(None)
}

async fn check_insecure_cookies(
    client: &Client,
    url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    if !url.starts_with("https://") {
        // Skip this check for non-HTTPS sites
        return Ok(None);
    }

    let resp = client.get(url).send().await.map_err(|e| {
        FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", url, e))
    })?;

    // Clone headers to avoid issues with borrowing
    let headers = resp.headers().clone();
    let mut insecure_cookies = Vec::new();

    if let Some(_cookie_headers) = headers.get_all("Set-Cookie").iter().peekable().peek() {
        for cookie_header in headers.get_all("Set-Cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                // Extract cookie name
                let name = cookie_str
                    .split(';')
                    .next()
                    .and_then(|name_value| name_value.split('=').next())
                    .unwrap_or("unknown")
                    .to_string();

                // Check if Secure flag is set
                let secure = cookie_str.to_lowercase().contains("secure");

                // Check if HttpOnly flag is set
                let http_only = cookie_str.to_lowercase().contains("httponly");

                if !secure || !http_only {
                    insecure_cookies.push(json!({
                        "name": name,
                        "secure": secure,
                        "httpOnly": http_only
                    }));
                }
            }
        }
    }

    if !insecure_cookies.is_empty() {
        let vuln = Vulnerability {
            id: "WEB-007".to_string(),
            name: "Insecure Cookie Configuration".to_string(),
            description:
                "The site sets cookies without proper security flags (Secure and/or HttpOnly)"
                    .to_string(),
            severity: Severity::Medium,
            location: url.to_string(),
            details: json!({
                "insecure_cookies": insecure_cookies,
                "recommendation": "Set both Secure and HttpOnly flags on all cookies containing sensitive data"
            }),
            exploitable: false,
        };

        return Ok(Some(vuln));
    }

    Ok(None)
}

async fn check_xss_enhanced(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    // 1. First get the page and look for forms
    let resp = client.get(base_url).send().await.map_err(|e| {
        FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", base_url, e))
    })?;

    let body = resp
        .text()
        .await
        .map_err(|e| FortiCoreError::NetworkError(format!("Failed to read response: {}", e)))?;

    // Look for forms and their target URLs
    let form_regex = Regex::new(r#"(?i)<form[^>]*action=["']([^"']*)["']"#).unwrap();
    let _param_regex = Regex::new(r"(?i)([^?&=]+)=([^&]*)").unwrap();

    // Also check for URL parameters in the original URL
    if base_url.contains('?') {
        let xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "';alert(1);//",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ];

        let parts: Vec<&str> = base_url.split('?').collect();
        if parts.len() >= 2 {
            let params_str = parts[1];
            let params: Vec<&str> = params_str.split('&').collect();

            for param in params {
                if param.contains('=') {
                    let param_parts: Vec<&str> = param.split('=').collect();
                    let param_name = param_parts[0];

                    // Try a simple XSS test
                    for payload in &xss_payloads {
                        let encoded_payload = urlencoding::encode(payload);
                        let test_url = format!("{}?{}={}", parts[0], param_name, encoded_payload);

                        let test_resp = client.get(&test_url).send().await.map_err(|e| {
                            FortiCoreError::NetworkError(format!(
                                "Failed to connect to {}: {}",
                                test_url, e
                            ))
                        })?;

                        let test_body = test_resp.text().await.map_err(|e| {
                            FortiCoreError::NetworkError(format!("Failed to read response: {}", e))
                        })?;

                        // Check if the payload was reflected
                        if test_body.contains(payload) {
                            let vuln = Vulnerability {
                                id: "WEB-008".to_string(),
                                name: "Reflected XSS Vulnerability".to_string(),
                                description: format!(
                                    "Parameter '{}' reflects unsanitized user input",
                                    param_name
                                ),
                                severity: Severity::High,
                                location: base_url.to_string(),
                                details: json!({
                                    "parameter": param_name,
                                    "payload": payload,
                                    "test_url": test_url,
                                    "reflected": true
                                }),
                                exploitable: true,
                            };

                            vulnerabilities.push(vuln);
                            break; // Found a vulnerability in this parameter, move to the next
                        }
                    }
                }
            }
        }
    }

    // Check forms for potential XSS
    for captures in form_regex.captures_iter(&body) {
        if let Some(form_action) = captures.get(1) {
            let form_url = form_action.as_str();
            let action_url = if form_url.starts_with("http") {
                form_url.to_string()
            } else if form_url.starts_with('/') {
                let url_parts: Vec<&str> = base_url.split('/').take(3).collect();
                format!(
                    "{}/{}",
                    url_parts.join("/"),
                    form_url.trim_start_matches('/')
                )
            } else {
                format!("{}/{}", base_url.trim_end_matches('/'), form_url)
            };

            // Just detect the form - we won't try to submit in the basic scan
            let vuln = Vulnerability {
                id: "WEB-004".to_string(),
                name: "Potential XSS Vulnerability".to_string(),
                description: "The page contains forms that could potentially be vulnerable to Cross-Site Scripting (XSS) attacks".to_string(),
                severity: Severity::Medium,
                location: action_url,
                details: json!({
                    "form_action": form_url,
                    "note": "Forms often accept user input which could be vulnerable to XSS if not properly sanitized"
                }),
                exploitable: true,
            };

            vulnerabilities.push(vuln);
        }
    }

    Ok(vulnerabilities)
}

async fn check_sql_injection_enhanced(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // SQL injection detection requires URL parameters
    if !base_url.contains('?') {
        return Ok(None); // No parameters to test
    }

    // Extract parameters
    let parts: Vec<&str> = base_url.split('?').collect();
    if parts.len() < 2 {
        return Ok(None);
    }

    let params_str = parts[1];
    let params: Vec<&str> = params_str.split('&').collect();

    // SQL injection payloads with different techniques
    let sql_payloads = [
        "' OR '1'='1",                 // Basic string-based
        "\" OR \"1\"=\"1",             // Double quote variant
        "1 OR 1=1",                    // Numeric-based
        "1' OR '1'='1' --",            // Comment-based
        "1\" OR \"1\"=\"1\" --",       // Double quote with comment
        "1' OR '1'='1' #",             // MySQL comment
        "' UNION SELECT 1,2,3 --",     // Union-based
        "') OR 1=1 --",                // Different bracket placement
        "'; WAITFOR DELAY '0:0:5' --", // Time-based (MS SQL)
        "'; SELECT pg_sleep(5) --",    // Time-based (PostgreSQL)
        "' OR sleep(5) #",             // Time-based (MySQL)
        "admin'--",                    // Authentication bypass
    ];

    // Error patterns that might indicate SQL injection vulnerability
    let sql_errors = [
        // MySQL
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "MySQLSyntaxErrorException",
        "valid MySQL result",
        // PostgreSQL
        "PG::Error:",
        "PostgreSQL ERROR:",
        // SQLite
        "SQLite/JDBCDriver",
        "SQLite.Exception",
        "System.Data.SQLite.SQLiteException",
        // MS SQL
        "Microsoft SQL Native Client error",
        "SQL Server",
        "OLE DB Provider for SQL Server",
        "Unclosed quotation mark",
        // Oracle
        "ORA-",
        "Oracle error",
        "Oracle Database",
        "SQL command not properly ended",
        // Generic
        "syntax error",
        "ODBC Driver",
        "error in your SQL syntax",
        "unexpected end of SQL command",
        "unterminated quoted string",
        "SQL syntax error",
        "SQLSTATE",
    ];

    // Test all parameters
    for param in &params {
        if !param.contains('=') {
            continue;
        }

        let param_parts: Vec<&str> = param.split('=').collect();
        if param_parts.len() < 2 {
            continue;
        }

        let param_name = param_parts[0];

        // Get baseline response
        let baseline_url = format!("{}?{}={}", parts[0], param_name, param_parts[1]);
        let baseline_resp = client.get(&baseline_url).send().await.map_err(|e| {
            FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", baseline_url, e))
        })?;

        let baseline_status = baseline_resp.status().as_u16();
        let baseline_body = baseline_resp
            .text()
            .await
            .map_err(|e| FortiCoreError::NetworkError(format!("Failed to read response: {}", e)))?;
        let baseline_len = baseline_body.len();

        // Try different payloads
        for payload in &sql_payloads {
            let encoded_payload = urlencoding::encode(payload);
            let test_url = format!("{}?{}={}", parts[0], param_name, encoded_payload);

            let test_resp = client.get(&test_url).send().await.map_err(|e| {
                FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", test_url, e))
            })?;

            let test_status = test_resp.status().as_u16();
            let test_body = test_resp.text().await.map_err(|e| {
                FortiCoreError::NetworkError(format!("Failed to read response: {}", e))
            })?;
            let test_len = test_body.len();

            // Check for SQL error messages
            for error in &sql_errors {
                if test_body.contains(error) {
                    let vuln = Vulnerability {
                        id: "WEB-005".to_string(),
                        name: "SQL Injection Vulnerability".to_string(),
                        description: format!(
                            "The parameter '{}' is vulnerable to SQL injection attacks",
                            param_name
                        ),
                        severity: Severity::High,
                        location: base_url.to_string(),
                        details: json!({
                            "parameter": param_name,
                            "payload": payload,
                            "error_detected": error,
                            "test_url": test_url,
                            "recommendation": "Use parameterized queries or prepared statements to prevent SQL injection"
                        }),
                        exploitable: true,
                    };

                    return Ok(Some(vuln));
                }
            }

            // Check for behavioral differences indicating successful injection
            // 1. Different HTTP status code
            if baseline_status != test_status && (test_status == 200 || baseline_status == 200) {
                // Changed from error to success or vice versa
                let vuln = Vulnerability {
                    id: "WEB-005".to_string(),
                    name: "Potential SQL Injection Vulnerability".to_string(),
                    description: format!(
                        "The parameter '{}' might be vulnerable to SQL injection attacks (status code change)",
                        param_name
                    ),
                    severity: Severity::High,
                    location: base_url.to_string(),
                    details: json!({
                        "parameter": param_name,
                        "payload": payload,
                        "baseline_status": baseline_status,
                        "test_status": test_status,
                        "test_url": test_url,
                        "recommendation": "Use parameterized queries or prepared statements to prevent SQL injection"
                    }),
                    exploitable: true,
                };

                return Ok(Some(vuln));
            }

            // 2. Significant change in response size
            let size_diff_percent =
                ((test_len as f64 - baseline_len as f64).abs() / baseline_len as f64) * 100.0;
            if size_diff_percent > 30.0 && test_status == 200 && baseline_status == 200 {
                // The response size changed significantly
                let vuln = Vulnerability {
                    id: "WEB-005".to_string(),
                    name: "Potential SQL Injection Vulnerability".to_string(),
                    description: format!(
                        "The parameter '{}' might be vulnerable to SQL injection attacks (response size change)",
                        param_name
                    ),
                    severity: Severity::High,
                    location: base_url.to_string(),
                    details: json!({
                        "parameter": param_name,
                        "payload": payload,
                        "baseline_length": baseline_len,
                        "test_length": test_len,
                        "size_difference_percent": format!("{:.1}%", size_diff_percent),
                        "test_url": test_url,
                        "recommendation": "Use parameterized queries or prepared statements to prevent SQL injection"
                    }),
                    exploitable: true,
                };

                return Ok(Some(vuln));
            }
        }
    }

    Ok(None)
}

async fn check_directory_traversal(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Directory traversal detection requires URL parameters
    if !base_url.contains('?') {
        return Ok(None);
    }

    // Extract parameters
    let parts: Vec<&str> = base_url.split('?').collect();
    if parts.len() < 2 {
        return Ok(None);
    }

    let params_str = parts[1];
    let params: Vec<&str> = params_str.split('&').collect();

    // Try with the first parameter
    if let Some(param) = params.first() {
        if !param.contains('=') {
            return Ok(None);
        }

        let param_parts: Vec<&str> = param.split('=').collect();
        if param_parts.len() < 2 {
            return Ok(None);
        }

        let param_name = param_parts[0];

        // Test directory traversal patterns
        let traversal_patterns = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\windows\\win.ini",
            "..%5C..%5C..%5Cwindows%5Cwin.ini",
        ];

        for pattern in &traversal_patterns {
            let test_url = format!("{}?{}={}", parts[0], param_name, pattern);

            let resp = client.get(&test_url).send().await.map_err(|e| {
                FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", test_url, e))
            })?;

            let body = resp.text().await.map_err(|e| {
                FortiCoreError::NetworkError(format!("Failed to read response: {}", e))
            })?;

            // Check for indicators of successful directory traversal
            let linux_indicators = ["root:x:", "nobody:x:", "bin:x:", "daemon:x:"];
            let windows_indicators = ["for 16-bit app support", "[fonts]", "[extensions]"];

            let mut found_indicator = false;

            for indicator in linux_indicators.iter().chain(windows_indicators.iter()) {
                if body.contains(indicator) {
                    found_indicator = true;
                    break;
                }
            }

            if found_indicator {
                let vuln = Vulnerability {
                    id: "WEB-009".to_string(),
                    name: "Directory Traversal Vulnerability".to_string(),
                    description: format!(
                        "The parameter '{}' is vulnerable to directory traversal attacks",
                        param_name
                    ),
                    severity: Severity::High,
                    location: base_url.to_string(),
                    details: json!({
                        "parameter": param_name,
                        "test_path": pattern,
                        "test_url": test_url,
                        "recommendation": "Validate and sanitize all file paths from user input"
                    }),
                    exploitable: true,
                };

                return Ok(Some(vuln));
            }
        }
    }

    Ok(None)
}

async fn check_lfi(client: &Client, base_url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    // LFI detection requires URL parameters
    if !base_url.contains('?') {
        return Ok(None);
    }

    // Extract parameters that might be referring to files
    let parts: Vec<&str> = base_url.split('?').collect();
    if parts.len() < 2 {
        return Ok(None);
    }

    let params_str = parts[1];
    let params: Vec<&str> = params_str.split('&').collect();

    // Look for parameters that might be file-related
    let file_param_keywords = ["file", "page", "include", "doc", "path", "src", "source"];

    for param in &params {
        if !param.contains('=') {
            continue;
        }

        let param_parts: Vec<&str> = param.split('=').collect();
        if param_parts.len() < 2 {
            continue;
        }

        let param_name = param_parts[0];
        let param_value = param_parts[1];

        // Check if parameter name suggests file operations
        let mut likely_file_param = false;
        for keyword in &file_param_keywords {
            if param_name.to_lowercase().contains(keyword) {
                likely_file_param = true;
                break;
            }
        }

        if likely_file_param || param_value.contains('.') {
            // Test LFI patterns
            let lfi_patterns = [
                "/etc/passwd",
                "/etc/hosts",
                "c:\\windows\\win.ini",
                "../../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
            ];

            for pattern in &lfi_patterns {
                let test_url = format!("{}?{}={}", parts[0], param_name, pattern);

                let resp = client.get(&test_url).send().await.map_err(|e| {
                    FortiCoreError::NetworkError(format!(
                        "Failed to connect to {}: {}",
                        test_url, e
                    ))
                })?;

                let _status = resp.status().as_u16();
                let body = resp.text().await.map_err(|e| {
                    FortiCoreError::NetworkError(format!("Failed to read response: {}", e))
                })?;

                // Check for indicators of successful LFI
                let indicators = [
                    "root:x:",
                    "localhost",
                    "for 16-bit app support",
                    "<?php",
                    "#!/bin/bash",
                    "#!/usr/bin/perl",
                ];

                for indicator in &indicators {
                    if body.contains(indicator) {
                        let vuln = Vulnerability {
                            id: "WEB-010".to_string(),
                            name: "Local File Inclusion Vulnerability".to_string(),
                            description: format!(
                                "The parameter '{}' is vulnerable to local file inclusion",
                                param_name
                            ),
                            severity: Severity::High,
                            location: base_url.to_string(),
                            details: json!({
                                "parameter": param_name,
                                "test_path": pattern,
                                "test_url": test_url,
                                "indicator_found": indicator,
                                "recommendation": "Validate and whitelist allowed files, avoid using user input for file paths"
                            }),
                            exploitable: true,
                        };

                        return Ok(Some(vuln));
                    }
                }

                // Check for Base64-encoded PHP content from the php:// filter
                if pattern.contains("php://filter") && body.len() > 100 {
                    // This is a heuristic check - normally we'd try to decode the Base64 and verify
                    // it's PHP code, but for the scanner we'll just check if it looks Base64-ish
                    let base64_regex = Regex::new(r"^[A-Za-z0-9+/=]+$").unwrap();
                    if base64_regex.is_match(&body.trim()) {
                        let vuln = Vulnerability {
                            id: "WEB-010".to_string(),
                            name: "Local File Inclusion Vulnerability".to_string(),
                            description: format!("The parameter '{}' is vulnerable to local file inclusion with PHP filters", param_name),
                            severity: Severity::High,
                            location: base_url.to_string(),
                            details: json!({
                                "parameter": param_name,
                                "test_path": pattern,
                                "test_url": test_url,
                                "php_filter_encoding": "Detected possible Base64-encoded source code",
                                "recommendation": "Validate and whitelist allowed files, avoid using user input for file paths"
                            }),
                            exploitable: true,
                        };

                        return Ok(Some(vuln));
                    }
                }
            }
        }
    }

    Ok(None)
}

async fn check_open_redirect(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Check for redirection parameters
    if !base_url.contains('?') {
        return Ok(None);
    }

    // Extract parameters
    let parts: Vec<&str> = base_url.split('?').collect();
    if parts.len() < 2 {
        return Ok(None);
    }

    let params_str = parts[1];
    let params: Vec<&str> = params_str.split('&').collect();

    // Look for parameters that might be related to redirection
    let redirect_param_keywords = [
        "redirect",
        "url",
        "return",
        "next",
        "target",
        "redir",
        "destination",
        "to",
        "link",
        "goto",
    ];

    for param in &params {
        if !param.contains('=') {
            continue;
        }

        let param_parts: Vec<&str> = param.split('=').collect();
        if param_parts.len() < 2 {
            continue;
        }

        let param_name = param_parts[0];

        // Check if parameter name suggests redirection
        let mut likely_redirect_param = false;
        for keyword in &redirect_param_keywords {
            if param_name.to_lowercase().contains(keyword) {
                likely_redirect_param = true;
                break;
            }
        }

        if likely_redirect_param {
            // Test open redirect with an external domain
            let test_domains = [
                "https://evil-example.com",
                "//evil-example.com",
                "evil-example.com",
            ];

            for test_domain in &test_domains {
                let test_url = format!("{}?{}={}", parts[0], param_name, test_domain);

                let resp = client.get(&test_url).send().await.map_err(|e| {
                    FortiCoreError::NetworkError(format!(
                        "Failed to connect to {}: {}",
                        test_url, e
                    ))
                })?;

                // Check if we got redirected to our malicious domain
                if let Some(location) = resp.headers().get("Location") {
                    let location_str = location.to_str().unwrap_or("");
                    if location_str.contains("evil-example.com") {
                        let vuln = Vulnerability {
                            id: "WEB-011".to_string(),
                            name: "Open Redirect Vulnerability".to_string(),
                            description: format!(
                                "The parameter '{}' is vulnerable to open redirect attacks",
                                param_name
                            ),
                            severity: Severity::Medium,
                            location: base_url.to_string(),
                            details: json!({
                                "parameter": param_name,
                                "test_url": test_url,
                                "redirect_to": location_str,
                                "recommendation": "Implement a whitelist of allowed redirect destinations or use relative URLs"
                            }),
                            exploitable: true,
                        };

                        return Ok(Some(vuln));
                    }
                }
            }
        }
    }

    Ok(None)
}

async fn check_jwt_vulnerabilities(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Make a request to the site to find any JWT tokens in cookies or response body
    let resp = client.get(base_url).send().await.map_err(|e| {
        FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", base_url, e))
    })?;

    // Clone the headers before consuming the response body
    let headers = resp.headers().clone();

    let body = resp
        .text()
        .await
        .map_err(|e| FortiCoreError::NetworkError(format!("Failed to read response: {}", e)))?;

    // Look for JWT tokens in cookies
    if let Some(_) = headers.get_all("Set-Cookie").iter().peekable().peek() {
        for cookie_header in headers.get_all("Set-Cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                // Extract cookie value
                let value = cookie_str
                    .split(';')
                    .next()
                    .and_then(|name_value| {
                        let parts: Vec<&str> = name_value.split('=').collect();
                        if parts.len() >= 2 {
                            Some(parts[1..].join("=")) // Handle values with = in them
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();

                // Extract cookie name
                let name = cookie_str
                    .split(';')
                    .next()
                    .and_then(|name_value| name_value.split('=').next())
                    .unwrap_or("unknown")
                    .to_string();

                // JWT tokens typically have 3 parts separated by dots
                if value.matches('.').count() == 2 && value.starts_with("eyJ") {
                    // This looks like a JWT token

                    // Check for the "none" algorithm vulnerability
                    let parts: Vec<&str> = value.split('.').collect();
                    if parts.len() == 3 {
                        let header_base64 = parts[0];

                        // Attempt to decode the header (simplified approach)
                        let padding_needed = (4 - header_base64.len() % 4) % 4;
                        let padded_header =
                            format!("{}{}", header_base64, "=".repeat(padding_needed));

                        if padded_header.contains("alg\":\"none")
                            || padded_header.contains("alg\":\"HS256")
                        {
                            let vuln = Vulnerability {
                                id: "WEB-012".to_string(),
                                name: "Potentially Insecure JWT Implementation".to_string(),
                                description: "The site uses JWT tokens which might be vulnerable to algorithm confusion attacks".to_string(),
                                severity: Severity::Medium,
                                location: base_url.to_string(),
                                details: json!({
                                    "cookie_name": name,
                                    "jwt_header": header_base64,
                                    "recommendation": "Use strong signing algorithms (RS256) and validate the 'alg' header"
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

    // Look for JWT tokens in the response body
    let jwt_regex = Regex::new(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+").unwrap();

    if let Some(captures) = jwt_regex.captures(&body) {
        if let Some(jwt_match) = captures.get(0) {
            let jwt = jwt_match.as_str();
            let parts: Vec<&str> = jwt.split('.').collect();

            if parts.len() == 3 {
                let header_base64 = parts[0];

                // Attempt to decode the header (simplified approach)
                let padding_needed = (4 - header_base64.len() % 4) % 4;
                let padded_header = format!("{}{}", header_base64, "=".repeat(padding_needed));

                if padded_header.contains("alg\":\"none") || padded_header.contains("alg\":\"HS256")
                {
                    let vuln = Vulnerability {
                        id: "WEB-012".to_string(),
                        name: "Potentially Insecure JWT Implementation".to_string(),
                        description: "The site uses JWT tokens which might be vulnerable to algorithm confusion attacks".to_string(),
                        severity: Severity::Medium,
                        location: base_url.to_string(),
                        details: json!({
                            "location": "response_body",
                            "jwt_header": header_base64,
                            "recommendation": "Use strong signing algorithms (RS256) and validate the 'alg' header"
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

async fn check_insecure_file_upload(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Get the page and look for file upload forms
    let resp = client.get(base_url).send().await.map_err(|e| {
        FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", base_url, e))
    })?;

    let body = resp
        .text()
        .await
        .map_err(|e| FortiCoreError::NetworkError(format!("Failed to read response: {}", e)))?;

    // Look for file upload forms
    let file_input_regex = Regex::new(r#"(?i)<input[^>]*type=["']file["'][^>]*>"#).unwrap();

    if file_input_regex.is_match(&body) {
        // Find the form that contains the file input
        let form_regex = Regex::new(r#"(?i)<form[^>]*>(.*?)</form>"#).unwrap();

        for form_captures in form_regex.captures_iter(&body) {
            if let Some(form_content) = form_captures.get(1) {
                if file_input_regex.is_match(form_content.as_str()) {
                    // This form has a file upload field
                    let vuln = Vulnerability {
                        id: "WEB-013".to_string(),
                        name: "Potential Insecure File Upload".to_string(),
                        description: "The site contains file upload functionality which could be vulnerable if not properly secured".to_string(),
                        severity: Severity::Medium,
                        location: base_url.to_string(),
                        details: json!({
                            "finding": "File upload form detected",
                            "recommendation": "Implement proper file type validation, size limits, and content scanning for uploaded files"
                        }),
                        exploitable: false,
                    };

                    return Ok(Some(vuln));
                }
            }
        }
    }

    Ok(None)
}

fn save_scan_results(vulnerabilities: &[Vulnerability], path: &Path) -> FortiCoreResult<()> {
    use std::fs::File;
    use std::io::Write;

    let results_json = serde_json::to_string_pretty(vulnerabilities)?;
    let mut file = File::create(path)?;
    file.write_all(results_json.as_bytes())?;

    Ok(())
}
