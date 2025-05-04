use crate::scanners::Vulnerability;
use crate::utils::error::{FortiCoreError, FortiCoreResult};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

/// Extracts the domain from a URL
pub fn extract_domain(url: &str) -> FortiCoreResult<String> {
    let parsed_url = match Url::parse(url) {
        Ok(url) => url,
        Err(_) => {
            // Try with http:// prefix if parsing failed
            match Url::parse(&format!("http://{}", url)) {
                Ok(url) => url,
                Err(e) => return Err(FortiCoreError::InvalidUrl(e.to_string())),
            }
        }
    };

    match parsed_url.host_str() {
        Some(host) => Ok(host.to_string()),
        None => Err(FortiCoreError::InvalidUrl(
            "URL does not contain a valid host".to_string(),
        )),
    }
}

/// Normalizes a URL by ensuring it has a scheme
pub fn normalize_url(url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    }
}

/// Creates a HTTP client with standard settings for scanning
pub fn create_client() -> FortiCoreResult<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")?,
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .default_headers(headers)
        .danger_accept_invalid_certs(true) // Accept invalid certificates for testing
        .build()?;

    Ok(client)
}

/// Saves scan results to a file
pub fn save_scan_results(vulnerabilities: &[Vulnerability], path: &Path) -> FortiCoreResult<()> {
    use std::fs::File;
    use std::io::Write;

    let json = serde_json::to_string_pretty(vulnerabilities)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}
