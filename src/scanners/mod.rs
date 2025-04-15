mod network_scanner;
mod port_scanner;
mod ssl_scanner;
mod vuln_scanner;
mod web_scanner;

use crate::utils::error::FortiCoreResult;
use crate::ScanType;
use std::path::Path;

pub struct ScanResult {
    pub target: String,
    pub scan_type: ScanType,
    pub vulnerabilities: Vec<Vulnerability>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub location: String,
    pub details: serde_json::Value,
    pub exploitable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

pub async fn run_scan(
    target: &str,
    scan_type: &ScanType,
    output_path: Option<&Path>,
    verbose: bool,
    scan_subdomains: bool,
) -> FortiCoreResult<()> {
    match scan_type {
        ScanType::Basic => basic_scan(target, output_path, verbose).await,
        ScanType::Network => network_scanner::scan(target, output_path, verbose).await,
        ScanType::Web => web_scanner::scan(target, output_path, verbose, scan_subdomains).await,
        ScanType::Vuln => vuln_scanner::scan(target, output_path, verbose).await,
        ScanType::SSL => ssl_scanner::scan(target, output_path, verbose).await,
        ScanType::Full => full_scan(target, output_path, verbose, scan_subdomains).await,
    }
}

async fn basic_scan(
    target: &str,
    output_path: Option<&Path>,
    verbose: bool,
) -> FortiCoreResult<()> {
    if verbose {
        println!("Running basic scan on {}", target);
    }

    // For now, just run a port scan as a basic scan
    let results = port_scanner::scan_ports(target, &[80, 443, 22, 21, 25, 3306, 5432]).await?;

    if verbose {
        for port in &results {
            println!(
                "Port {} is {}",
                port.number,
                if port.open { "open" } else { "closed" }
            );
        }
    }

    // Save results if output path is provided
    if let Some(path) = output_path {
        save_scan_results(target, &ScanType::Basic, results, path, verbose)?;
    }

    Ok(())
}

async fn full_scan(
    target: &str,
    output_path: Option<&Path>,
    verbose: bool,
    scan_subdomains: bool,
) -> FortiCoreResult<()> {
    if verbose {
        println!("Running full scan on {}", target);
    }

    // Run all scan types
    network_scanner::scan(target, None, verbose).await?;
    web_scanner::scan(target, None, verbose, scan_subdomains).await?;
    vuln_scanner::scan(target, None, verbose).await?;
    ssl_scanner::scan(target, None, verbose).await?;

    // Also run a more thorough port scan
    let ports = port_scanner::scan_common_ports(target).await?;

    if verbose {
        println!(
            "Found {} open ports",
            ports.iter().filter(|p| p.open).count()
        );
    }

    // Save combined results if output path is provided
    if let Some(path) = output_path {
        save_scan_results(target, &ScanType::Full, ports, path, verbose)?;
    }

    Ok(())
}

fn save_scan_results<T: serde::Serialize>(
    target: &str,
    scan_type: &ScanType,
    results: T,
    path: &Path,
    verbose: bool,
) -> FortiCoreResult<()> {
    use std::fs::File;
    use std::io::Write;

    if verbose {
        println!("Saving scan results to {}", path.display());
    }

    // Check if results is a Vec<PortResult>
    // If so, transform it into vulnerabilities format
    let results_json = if let Ok(port_results) = serde_json::to_value(&results) {
        if port_results.is_array() {
            let array = port_results.as_array().unwrap();
            if !array.is_empty() && array[0].get("number").is_some() {
                // This is a port scan result, convert to vulnerability format
                let mut vulnerabilities = Vec::new();
                let timestamp = chrono::Utc::now();

                for port_value in array {
                    if let (Some(number), Some(open), Some(service)) = (
                        port_value.get("number").and_then(|n| n.as_u64()),
                        port_value.get("open").and_then(|o| o.as_bool()),
                        port_value.get("service"),
                    ) {
                        if open {
                            let service_name = service.as_str().unwrap_or("Unknown");
                            let vuln = serde_json::json!({
                                "id": format!("PORT-{}", number),
                                "name": format!("Open Port {}", number),
                                "description": format!("Port {} is open and running {} service", number, service_name),
                                "severity": "Info",
                                "location": format!("{}:{}", target, number),
                                "details": {
                                    "port": number,
                                    "service": service_name
                                },
                                "exploitable": false
                            });
                            vulnerabilities.push(vuln);
                        }
                    }
                }

                let result = serde_json::json!({
                    "target": target,
                    "scan_type": format!("{:?}", scan_type),
                    "timestamp": timestamp.to_rfc3339(),
                    "vulnerabilities": vulnerabilities
                });

                serde_json::to_string_pretty(&result).unwrap()
            } else {
                serde_json::to_string_pretty(&results).unwrap()
            }
        } else {
            serde_json::to_string_pretty(&results).unwrap()
        }
    } else {
        serde_json::to_string_pretty(&results).unwrap()
    };

    let mut file = File::create(path)?;
    file.write_all(results_json.as_bytes())?;

    Ok(())
}
