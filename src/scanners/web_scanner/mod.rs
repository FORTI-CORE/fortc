pub mod auth;
pub mod cms;
pub mod common;
pub mod subdomain;
pub mod utils;

use crate::scanners::{Severity, Vulnerability};
use crate::utils::{error::FortiCoreResult, FortiCoreError};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

/// Main web scanner function that orchestrates the scanning process
pub async fn scan(
    target: &str,
    output_path: Option<&Path>,
    verbose: bool,
    scan_subdomains: bool,
) -> FortiCoreResult<()> {
    if verbose {
        println!("Starting web scan on target: {}", target);
    }

    // Normalize the target URL for subdomain enumeration
    let target_url = utils::normalize_url(target);
    let domain = utils::extract_domain(&target_url)?;

    // Create HTTP client
    let client = utils::create_client()?;

    // List to store all vulnerabilities
    let mut all_vulnerabilities = Vec::new();

    // Step 1: Perform subdomain enumeration if enabled
    let subdomains = if scan_subdomains {
        if verbose {
            println!("Enumerating subdomains for: {}", domain);
        }
        subdomain::enumerate_subdomains(&client, &domain, verbose).await?
    } else {
        if verbose {
            println!("Subdomain scanning is disabled");
        }
        HashSet::new()
    };

    // If no subdomains found or scanning is disabled, just scan the main domain
    if subdomains.is_empty() {
        if verbose {
            println!("Scanning only the main domain");
        }

        let vulnerabilities = scan_single_target(&client, &target_url, verbose).await?;
        all_vulnerabilities.extend(vulnerabilities);
    } else {
        // Scan main domain first
        if verbose {
            println!("Scanning main domain: {}", target_url);
        }
        let vulnerabilities = scan_single_target(&client, &target_url, verbose).await?;
        all_vulnerabilities.extend(vulnerabilities);

        // Scan each subdomain
        for subdomain in &subdomains {
            let subdomain_url = format!("https://{}", subdomain);

            if verbose {
                println!("Scanning subdomain: {}", subdomain_url);
            }

            // Sleep briefly between scans to avoid overwhelming the server
            sleep(Duration::from_millis(500)).await;

            match scan_single_target(&client, &subdomain_url, verbose).await {
                Ok(vulnerabilities) => {
                    all_vulnerabilities.extend(vulnerabilities);
                }
                Err(e) => {
                    if verbose {
                        println!("Error scanning {}: {}", subdomain_url, e);
                    }

                    // Try with HTTP if HTTPS fails
                    let http_url = format!("http://{}", subdomain);
                    if verbose {
                        println!("Retrying with HTTP: {}", http_url);
                    }

                    match scan_single_target(&client, &http_url, verbose).await {
                        Ok(vulnerabilities) => {
                            all_vulnerabilities.extend(vulnerabilities);
                        }
                        Err(e) => {
                            if verbose {
                                println!("Error scanning {}: {}", http_url, e);
                            }
                        }
                    }
                }
            }
        }
    }

    if verbose {
        println!(
            "Web scan completed. Found {} vulnerabilities across all domains.",
            all_vulnerabilities.len()
        );
        for vuln in &all_vulnerabilities {
            println!(
                "- {} ({:?}): {} - {}",
                vuln.name, vuln.severity, vuln.location, vuln.description
            );
        }
    }

    // Save results if output path is provided
    if let Some(path) = output_path {
        utils::save_scan_results(&all_vulnerabilities, path)?;
    }

    Ok(())
}

// Function to scan a single target (domain or subdomain)
async fn scan_single_target(
    client: &reqwest::Client,
    target_url: &str,
    verbose: bool,
) -> FortiCoreResult<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    // Basic information gathering
    if verbose {
        println!("Gathering basic information about: {}", target_url);
    }

    // Check for HTTP response headers
    match common::check_headers(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking headers: {}", e);
            }
        }
        _ => {}
    }

    // Check for robots.txt
    if verbose {
        println!("Checking for robots.txt on: {}", target_url);
    }
    match common::check_robots_txt(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking robots.txt: {}", e);
            }
        }
        _ => {}
    }

    // Check for CMS detection
    if verbose {
        println!("Detecting CMS platform on: {}", target_url);
    }
    match cms::detect_cms(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error detecting CMS: {}", e);
            }
        }
        _ => {}
    }

    // Check for server version
    if verbose {
        println!("Checking for server version disclosure on: {}", target_url);
    }
    match common::check_server_version_disclosure(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking server version: {}", e);
            }
        }
        _ => {}
    }

    // Check for common vulnerabilities
    if verbose {
        println!("Checking for common web vulnerabilities on: {}", target_url);
    }

    // CORS misconfiguration
    match common::check_cors(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking CORS: {}", e);
            }
        }
        _ => {}
    }

    // Insecure cookies
    match common::check_insecure_cookies(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking cookies: {}", e);
            }
        }
        _ => {}
    }

    // XSS vulnerabilities
    match common::check_xss_enhanced(client, target_url).await {
        Ok(vulns) => vulnerabilities.extend(vulns),
        Err(e) => {
            if verbose {
                println!("Error checking XSS: {}", e);
            }
        }
    }

    // SQL injection
    match common::check_sql_injection_enhanced(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking SQL injection: {}", e);
            }
        }
        _ => {}
    }

    // Directory traversal
    match common::check_directory_traversal(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking directory traversal: {}", e);
            }
        }
        _ => {}
    }

    // Local File Inclusion
    match common::check_lfi(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking LFI: {}", e);
            }
        }
        _ => {}
    }

    // Open redirect
    match common::check_open_redirect(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking open redirect: {}", e);
            }
        }
        _ => {}
    }

    // JWT vulnerabilities
    match auth::check_jwt_vulnerabilities(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking JWT: {}", e);
            }
        }
        _ => {}
    }

    // Insecure file upload
    match common::check_insecure_file_upload(client, target_url).await {
        Ok(Some(vuln)) => vulnerabilities.push(vuln),
        Err(e) => {
            if verbose {
                println!("Error checking file upload: {}", e);
            }
        }
        _ => {}
    }

    Ok(vulnerabilities)
}
