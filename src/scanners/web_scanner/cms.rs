use crate::scanners::{Severity, Vulnerability};
use crate::utils::error::FortiCoreResult;
use regex::Regex;
use reqwest::Client;
use serde_json::json;

/// Detects Content Management Systems (CMS) and checks for known vulnerabilities
pub async fn detect_cms(client: &Client, url: &str) -> FortiCoreResult<Option<Vulnerability>> {
    // Define CMS fingerprints
    let cms_fingerprints = [
        // WordPress
        CmsFingerprint {
            name: "WordPress",
            paths: &[
                "/wp-login.php",
                "/wp-admin/",
                "/wp-content/",
                "/wp-includes/",
                "/wp-json/",
                "/wp-admin/admin-ajax.php",
            ],
            content_patterns: &["wp-content", "WordPress", "woocommerce"],
            meta_patterns: &["name=\"generator\" content=\"WordPress", "wp-settings"],
            version_patterns: &[("/readme.html", r"<br />\s*[Vv]ersion\s+(\d+\.\d+[\.\d]*)")],
            headers: &["X-Powered-By: WordPress"],
        },
        // Drupal
        CmsFingerprint {
            name: "Drupal",
            paths: &[
                "/core/",
                "/sites/",
                "/modules/",
                "/includes/",
                "/misc/drupal.js",
                "/CHANGELOG.txt",
            ],
            content_patterns: &["Drupal.settings", "Drupal.behaviors", "drupal-core"],
            meta_patterns: &["name=\"Generator\" content=\"Drupal"],
            version_patterns: &[("/CHANGELOG.txt", r"Drupal (\d+\.\d+[\.\d]*)")],
            headers: &["X-Generator: Drupal"],
        },
        // Joomla
        CmsFingerprint {
            name: "Joomla",
            paths: &[
                "/administrator/",
                "/components/",
                "/modules/",
                "/templates/",
                "/media/jui/",
                "/libraries/joomla/",
            ],
            content_patterns: &["joomla", "Joomla!", "com_content"],
            meta_patterns: &["name=\"generator\" content=\"Joomla", "content=\"Joomla"],
            version_patterns: &[
                // For older Joomla versions
                (
                    "/language/en-GB/en-GB.xml",
                    r"<version>(\d+\.\d+[\.\d]*)</version>",
                ),
                // For newer Joomla versions
                (
                    "/administrator/manifests/files/joomla.xml",
                    r"<version>(\d+\.\d+[\.\d]*)</version>",
                ),
            ],
            headers: &["X-Content-Powered-By: Joomla"],
        },
        // Magento
        CmsFingerprint {
            name: "Magento",
            paths: &[
                "/magento/",
                "/skin/",
                "/media/",
                "/app/",
                "/js/varien/",
                "/downloader/",
                "/js/mage/",
            ],
            content_patterns: &["Mage.", "magento", "Magento_", "skin/frontend/"],
            meta_patterns: &["Magento, Varien, Sun, ROR"],
            version_patterns: &[
                // Difficult to reliably detect Magento version without authentication
                ("/RELEASE_NOTES.txt", r"CE\s+(\d+\.\d+[\.\d]*)"),
            ],
            headers: &["X-Magento-Version"],
        },
    ];

    // Try to detect CMS
    for fingerprint in &cms_fingerprints {
        let mut indicators = Vec::new();
        let mut version = None;

        // Check for common paths
        for &path in fingerprint.paths {
            let target_url = if url.ends_with('/') {
                format!("{}{}", url, path.trim_start_matches('/'))
            } else {
                format!("{}{}", url, path)
            };

            match client.get(&target_url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        indicators.push(format!("Found path: {}", path));

                        // If this is a version pattern URL, try to extract version
                        for &(version_path, version_regex) in fingerprint.version_patterns {
                            if path == version_path {
                                // Clone the response to avoid move issues
                                if let Ok(content) = resp.text().await {
                                    if let Some(captures) =
                                        Regex::new(version_regex).unwrap().captures(&content)
                                    {
                                        if let Some(ver) = captures.get(1) {
                                            version = Some(ver.as_str().to_string());
                                            break;
                                        }
                                    }
                                }
                                // We've consumed this response, break out of the version pattern loop
                                break;
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        // If we have enough indicators, consider it a match
        if !indicators.is_empty() {
            // Look for content patterns and metadata in the homepage
            let homepage_response = match client.get(url).send().await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            // Clone the response for text extraction to avoid move issues
            let content = match homepage_response.text().await {
                Ok(text) => text,
                Err(_) => continue,
            };

            // We've consumed the homepage_response with text(), so we need to make a new request
            // to get the headers for later use
            let headers_response = match client.get(url).send().await {
                Ok(resp) => resp.headers().clone(),
                Err(_) => continue,
            };

            // Check for content patterns
            for &pattern in fingerprint.content_patterns {
                if content.contains(pattern) {
                    indicators.push(format!("Found content pattern: {}", pattern));
                }
            }

            // Check for meta patterns
            for &pattern in fingerprint.meta_patterns {
                if content.contains(pattern) {
                    indicators.push(format!("Found meta pattern: {}", pattern));

                    // Try to extract version from generator meta tag if not already found
                    if version.is_none() && pattern.contains("generator") {
                        let re = Regex::new(&format!(
                            r"{}\s+(\d+\.\d+[\.\d]*)",
                            pattern.replace("content=\"", "content=\"[^\"]*")
                        ))
                        .unwrap();

                        if let Some(captures) = re.captures(&content) {
                            if let Some(ver) = captures.get(1) {
                                version = Some(ver.as_str().to_string());
                            }
                        }
                    }
                }
            }

            // Check for specific headers (now using our headers_response)
            for &header_pattern in fingerprint.headers {
                let parts: Vec<&str> = header_pattern.split(": ").collect();
                if parts.len() == 2 {
                    let header_name = parts[0];
                    let header_value = parts[1];

                    if let Some(header) = headers_response.get(header_name) {
                        if let Ok(value) = header.to_str() {
                            if value.contains(header_value) {
                                indicators.push(format!("Found header: {}", header_pattern));

                                // Try to extract version from header if not already found
                                if version.is_none() && value.contains(".") {
                                    let re = Regex::new(r"(\d+\.\d+[\.\d]*)").unwrap();
                                    if let Some(captures) = re.captures(value) {
                                        if let Some(ver) = captures.get(1) {
                                            version = Some(ver.as_str().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // If we have enough indicators (at least 2), consider it a match
            if indicators.len() >= 2 {
                let mut vulnerabilities = Vec::new();

                // Check for known vulnerabilities if version is known
                if let Some(ver) = &version {
                    vulnerabilities = check_cms_vulnerabilities(fingerprint.name, ver);
                }

                let severity = if !vulnerabilities.is_empty() {
                    Severity::High
                } else {
                    Severity::Info
                };

                let description = if let Some(ver) = &version {
                    if !vulnerabilities.is_empty() {
                        format!(
                            "{} {} detected with known vulnerabilities.",
                            fingerprint.name, ver
                        )
                    } else {
                        format!("{} {} detected.", fingerprint.name, ver)
                    }
                } else {
                    format!("{} detected (version unknown).", fingerprint.name)
                };

                let vuln = Vulnerability {
                    id: format!("WEB-CMS-{}", fingerprint.name.to_uppercase()),
                    name: format!("{} CMS Detected", fingerprint.name),
                    description,
                    severity,
                    location: url.to_string(),
                    details: json!({
                        "cms": fingerprint.name,
                        "version": version,
                        "indicators": indicators,
                        "known_vulnerabilities": vulnerabilities
                    }),
                    exploitable: !vulnerabilities.is_empty(),
                };

                return Ok(Some(vuln));
            }
        }
    }

    Ok(None)
}

/// CMS fingerprint struct for detection
struct CmsFingerprint<'a> {
    name: &'a str,
    paths: &'a [&'a str],
    content_patterns: &'a [&'a str],
    meta_patterns: &'a [&'a str],
    version_patterns: &'a [(&'a str, &'a str)],
    headers: &'a [&'a str],
}

/// Checks for known vulnerabilities in a detected CMS
fn check_cms_vulnerabilities(cms: &str, version: &str) -> Vec<String> {
    let mut vulnerabilities = Vec::new();

    match cms {
        "WordPress" => {
            // Check for known WordPress vulnerabilities
            if version_lt(version, "4.7.1") {
                vulnerabilities.push(
                    "WordPress REST API Content Injection vulnerability (CVE-2017-1001000)"
                        .to_string(),
                );
            }
            if version_lt(version, "4.7.2") {
                vulnerabilities.push(
                    "WordPress SQL Injection vulnerability in WP_Query (CVE-2017-9061)".to_string(),
                );
            }
            if version_lt(version, "4.9.6") {
                vulnerabilities
                    .push("WordPress GDPR compliance vulnerability (CVE-2018-12895)".to_string());
            }
            if version_lt(version, "5.0.0") {
                vulnerabilities.push(
                    "Older WordPress version with multiple known vulnerabilities".to_string(),
                );
            }
            // Add more as needed...
        }
        "Drupal" => {
            // Check for known Drupal vulnerabilities
            if version.starts_with("7.") && version_lt(version, "7.58") {
                vulnerabilities
                    .push("Drupal Drupalgeddon 2 RCE vulnerability (CVE-2018-7600)".to_string());
            }
            if version.starts_with("8.") && version_lt(version, "8.5.1") {
                vulnerabilities
                    .push("Drupal Drupalgeddon 2 RCE vulnerability (CVE-2018-7600)".to_string());
            }
            if version.starts_with("7.") && version_lt(version, "7.59") {
                vulnerabilities
                    .push("Drupal Drupalgeddon 3 RCE vulnerability (CVE-2018-7602)".to_string());
            }
            // Add more as needed...
        }
        "Joomla" => {
            // Check for known Joomla vulnerabilities
            if version_lt(version, "3.7.1") {
                vulnerabilities
                    .push("Joomla SQL Injection vulnerability (CVE-2017-8917)".to_string());
            }
            if version_lt(version, "3.6.4") {
                vulnerabilities
                    .push("Joomla Account Creation vulnerability (CVE-2016-8869)".to_string());
            }
            if version_lt(version, "3.4.4") {
                vulnerabilities
                    .push("Joomla Session Injection vulnerability (CVE-2015-8562)".to_string());
            }
            // Add more as needed...
        }
        "Magento" => {
            // Check for known Magento vulnerabilities
            if version.starts_with("1.") {
                vulnerabilities.push(
                    "Magento 1.x is End-of-Life and no longer receives security updates"
                        .to_string(),
                );
            }
            if version_lt(version, "2.2.0") {
                vulnerabilities.push(
                    "Multiple XSS and CSRF vulnerabilities in older Magento versions".to_string(),
                );
            }
            if version.starts_with("2.") && version_lt(version, "2.3.0") {
                vulnerabilities
                    .push("Magento SQL Injection vulnerability (CVE-2019-8118)".to_string());
            }
            // Add more as needed...
        }
        _ => {}
    }

    vulnerabilities
}

/// Compares version strings to determine if v1 is less than v2
fn version_lt(v1: &str, v2: &str) -> bool {
    let v1_parts: Vec<&str> = v1.split(".").collect();
    let v2_parts: Vec<&str> = v2.split(".").collect();

    let max_parts = v1_parts.len().max(v2_parts.len());

    for i in 0..max_parts {
        let v1_part = if i < v1_parts.len() {
            v1_parts[i].parse::<u32>().unwrap_or(0)
        } else {
            0
        };

        let v2_part = if i < v2_parts.len() {
            v2_parts[i].parse::<u32>().unwrap_or(0)
        } else {
            0
        };

        if v1_part < v2_part {
            return true;
        } else if v1_part > v2_part {
            return false;
        }
    }

    // Versions are equal
    false
}
