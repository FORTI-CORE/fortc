use crate::scanners::port_scanner;
use crate::scanners::{Severity, Vulnerability};
use crate::utils::{error::FortiCoreResult, FortiCoreError};
use serde_json::json;
use std::path::Path;

pub async fn scan(target: &str, output_path: Option<&Path>, verbose: bool) -> FortiCoreResult<()> {
    if verbose {
        println!("Starting network scan on target: {}", target);
    }

    let mut vulnerabilities = Vec::new();

    // Scan common service ports
    if verbose {
        println!("Scanning common service ports...");
    }

    let service_ports = &[
        21,    // FTP
        22,    // SSH
        23,    // Telnet
        25,    // SMTP
        53,    // DNS
        80,    // HTTP
        110,   // POP3
        111,   // RPC
        135,   // MS-RPC
        139,   // NetBIOS
        445,   // SMB
        1433,  // MSSQL
        1521,  // Oracle
        3306,  // MySQL
        3389,  // RDP
        5432,  // PostgreSQL
        5900,  // VNC
        6379,  // Redis
        8080,  // HTTP alternative
        27017, // MongoDB
    ];

    let port_results = port_scanner::scan_ports(target, service_ports).await?;

    // Count open ports for output message
    let open_ports_count = port_results.iter().filter(|p| p.open).count();

    // Check for insecure services
    if verbose {
        println!("Checking for insecure services...");
    }

    // Check for open Telnet
    if let Some(port) = port_results.iter().find(|p| p.number == 23 && p.open) {
        let vuln = Vulnerability {
            id: "NET-001".to_string(),
            name: "Telnet Service Enabled".to_string(),
            description: "Telnet service is enabled, which transmits data in cleartext and is considered insecure".to_string(),
            severity: Severity::High,
            location: format!("{}:{}", target, port.number),
            details: json!({
                "port": port.number,
                "service": port.service,
                "recommendation": "Disable Telnet and use SSH instead"
            }),
            exploitable: true,
        };
        vulnerabilities.push(vuln);
    }

    // Check for FTP
    if let Some(port) = port_results.iter().find(|p| p.number == 21 && p.open) {
        let vuln = Vulnerability {
            id: "NET-002".to_string(),
            name: "FTP Service Enabled".to_string(),
            description: "FTP service is enabled, which may transmit data in cleartext".to_string(),
            severity: Severity::Medium,
            location: format!("{}:{}", target, port.number),
            details: json!({
                "port": port.number,
                "service": port.service,
                "recommendation": "Use SFTP or FTPS instead of standard FTP"
            }),
            exploitable: true,
        };
        vulnerabilities.push(vuln);
    }

    // Check for open database ports directly accessible
    let db_ports = [1433, 3306, 5432, 6379, 27017];
    for &db_port in &db_ports {
        if let Some(port) = port_results.iter().find(|p| p.number == db_port && p.open) {
            let (name, db_type) = match db_port {
                1433 => ("Microsoft SQL Server", "MSSQL"),
                3306 => ("MySQL Database", "MySQL"),
                5432 => ("PostgreSQL Database", "PostgreSQL"),
                6379 => ("Redis Server", "Redis"),
                27017 => ("MongoDB Server", "MongoDB"),
                _ => unreachable!(),
            };

            let vuln = Vulnerability {
                id: format!(
                    "NET-{:03}",
                    10 + db_ports.iter().position(|&p| p == db_port).unwrap_or(0)
                ),
                name: format!("{} Exposed", name),
                description: format!("{} is directly accessible from the network", name),
                severity: Severity::High,
                location: format!("{}:{}", target, port.number),
                details: json!({
                    "port": port.number,
                    "database_type": db_type,
                    "recommendation": "Restrict database access using firewall rules and ensure authentication is properly configured"
                }),
                exploitable: true,
            };
            vulnerabilities.push(vuln);
        }
    }

    // Check for open Remote Desktop
    if let Some(port) = port_results.iter().find(|p| p.number == 3389 && p.open) {
        let vuln = Vulnerability {
            id: "NET-006".to_string(),
            name: "Remote Desktop Service Exposed".to_string(),
            description: "Remote Desktop Protocol (RDP) service is accessible from the network"
                .to_string(),
            severity: Severity::Medium,
            location: format!("{}:{}", target, port.number),
            details: json!({
                "port": port.number,
                "service": port.service,
                "recommendation": "Restrict RDP access using firewall rules or a VPN"
            }),
            exploitable: true,
        };
        vulnerabilities.push(vuln);
    }

    // Check for NetBIOS and SMB
    if port_results
        .iter()
        .any(|p| (p.number == 139 || p.number == 445) && p.open)
    {
        let vuln = Vulnerability {
            id: "NET-007".to_string(),
            name: "NetBIOS/SMB Services Exposed".to_string(),
            description: "NetBIOS and/or SMB services are accessible from the network, which could expose shared resources".to_string(),
            severity: Severity::Medium,
            location: format!("{}", target),
            details: json!({
                "ports": port_results.iter()
                    .filter(|p| (p.number == 139 || p.number == 445) && p.open)
                    .map(|p| p.number)
                    .collect::<Vec<_>>(),
                "recommendation": "Restrict access to these ports if not needed, or ensure they are properly secured"
            }),
            exploitable: true,
        };
        vulnerabilities.push(vuln);
    }

    if verbose {
        println!(
            "Network scan completed. Found {} vulnerabilities.",
            vulnerabilities.len()
        );
        for vuln in &vulnerabilities {
            println!(
                "- {} ({:?}): {}",
                vuln.name, vuln.severity, vuln.description
            );
        }
        println!("Found {} open ports", open_ports_count);
    }

    // Save results if output path is provided
    if let Some(path) = output_path {
        save_scan_results(&vulnerabilities, path)?;
    }

    Ok(())
}

fn save_scan_results(vulnerabilities: &[Vulnerability], path: &Path) -> FortiCoreResult<()> {
    use std::fs::File;
    use std::io::Write;

    let results_json = serde_json::to_string_pretty(vulnerabilities)?;
    let mut file = File::create(path)?;
    file.write_all(results_json.as_bytes())?;

    Ok(())
}
