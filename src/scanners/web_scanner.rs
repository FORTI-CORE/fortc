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

    // Check for common vulnerabilities
    if verbose {
        println!("Checking for common web vulnerabilities...");
    }

    // CORS misconfiguration
    let cors = check_cors(&client, &target_url).await?;
    if let Some(vuln) = cors {
        vulnerabilities.push(vuln);
    }

    // XSS reflection test (basic)
    let xss = check_xss(&client, &target_url).await?;
    if let Some(vuln) = xss {
        vulnerabilities.push(vuln);
    }

    // SQL Injection test (basic)
    let sqli = check_sql_injection(&client, &target_url).await?;
    if let Some(vuln) = sqli {
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

async fn check_xss(client: &Client, url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    // Very basic XSS check - look for parameters in the URL that might be vulnerable
    let resp = client.get(url).send().await.map_err(|e| {
        FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", url, e))
    })?;

    let body = resp
        .text()
        .await
        .map_err(|e| FortiCoreError::NetworkError(format!("Failed to read response: {}", e)))?;

    // Look for forms that might be vulnerable
    let form_regex = Regex::new(r"<form[^>]*>").unwrap();
    let input_regex = Regex::new(r"<input[^>]*>").unwrap();

    if form_regex.is_match(&body) && input_regex.is_match(&body) {
        let vuln = Vulnerability {
            id: "WEB-004".to_string(),
            name: "Potential XSS Vulnerability".to_string(),
            description: "The page contains forms that could potentially be vulnerable to Cross-Site Scripting (XSS) attacks".to_string(),
            severity: Severity::Medium,
            location: url.to_string(),
            details: json!({
                "forms_detected": form_regex.find_iter(&body).count(),
                "inputs_detected": input_regex.find_iter(&body).count(),
                "note": "This is a potential vulnerability that requires manual verification",
            }),
            exploitable: true,
        };

        return Ok(Some(vuln));
    }

    Ok(None)
}

async fn check_sql_injection(
    client: &Client,
    base_url: &str,
) -> FortiCoreResult<Option<Vulnerability>> {
    // Look for URL parameters that might be vulnerable to SQL injection
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

    // Test the first parameter with a simple SQL injection test
    if let Some(param) = params.first() {
        if !param.contains('=') {
            return Ok(None);
        }

        let param_parts: Vec<&str> = param.split('=').collect();
        if param_parts.len() < 2 {
            return Ok(None);
        }

        let param_name = param_parts[0];
        let base_param_url = format!("{}?{}=", parts[0], param_name);

        // Try a simple SQL injection test
        let test_url = format!("{}'{} OR '1'='1", base_param_url, param_parts[1]);

        let resp = client.get(&test_url).send().await.map_err(|e| {
            FortiCoreError::NetworkError(format!("Failed to connect to {}: {}", test_url, e))
        })?;

        let body = resp
            .text()
            .await
            .map_err(|e| FortiCoreError::NetworkError(format!("Failed to read response: {}", e)))?;

        // Look for error messages that might indicate SQL injection vulnerability
        let sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite3::",
            "SQLITE_ERROR",
            "Microsoft OLE DB Provider for SQL Server",
            "Error Executing Database Query",
            "Unclosed quotation mark",
            "ODBC Driver",
            "Microsoft Access Driver",
            "Oracle error",
        ];

        for error in &sql_errors {
            if body.contains(error) {
                let vuln = Vulnerability {
                    id: "WEB-005".to_string(),
                    name: "Potential SQL Injection Vulnerability".to_string(),
                    description: format!(
                        "The parameter '{}' might be vulnerable to SQL injection attacks",
                        param_name
                    ),
                    severity: Severity::High,
                    location: base_url.to_string(),
                    details: json!({
                        "parameter": param_name,
                        "error_detected": error,
                        "test_url": test_url,
                    }),
                    exploitable: true,
                };

                return Ok(Some(vuln));
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
