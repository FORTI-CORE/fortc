use crate::utils::{error::FortiCoreResult, FortiCoreError};
use futures::future;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const TIMEOUT_DURATION: Duration = Duration::from_secs(2);
const COMMON_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 989, 990, 993, 995, 1433,
    1521, 1723, 3306, 3389, 5060, 5432, 5900, 6543, 8080, 8443, 9090, 9099, 9100,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub number: u16,
    pub open: bool,
    pub service: Option<String>,
}

pub async fn scan_ports(target: &str, ports: &[u16]) -> FortiCoreResult<Vec<PortResult>> {
    // First try to use nmap if it's available
    if let Ok(results) = try_nmap_scan(target, ports).await {
        return Ok(results);
    }

    // Fall back to the built-in scanner if nmap isn't available
    // Resolve the target to an IP address
    let socket_addr = match resolve_target(target) {
        Ok(addr) => addr,
        Err(_) => {
            return Err(FortiCoreError::NetworkError(format!(
                "Failed to resolve target: {}",
                target
            )))
        }
    };

    let futures = ports.iter().map(|&port| scan_port(socket_addr, port));
    let results = future::join_all(futures).await;

    Ok(results)
}

pub async fn scan_common_ports(target: &str) -> FortiCoreResult<Vec<PortResult>> {
    scan_ports(target, COMMON_PORTS).await
}

async fn scan_port(target: IpAddr, port: u16) -> PortResult {
    let addr = format!("{}:{}", target, port);

    let result = timeout(TIMEOUT_DURATION, TcpStream::connect(&addr)).await;

    let open = result.is_ok() && result.unwrap().is_ok();
    let service = if open { identify_service(port) } else { None };

    PortResult {
        number: port,
        open,
        service,
    }
}

pub fn resolve_target(target: &str) -> std::io::Result<IpAddr> {
    // If target is already an IP address, parse it directly
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Otherwise try to resolve it as a hostname
    let socket_addrs = format!("{}:80", target).to_socket_addrs()?;
    let socket_addr = socket_addrs.into_iter().next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Could not resolve hostname: {}", target),
        )
    })?;

    Ok(socket_addr.ip())
}

fn identify_service(port: u16) -> Option<String> {
    match port {
        20 | 21 => Some("FTP".to_string()),
        22 => Some("SSH".to_string()),
        23 => Some("Telnet".to_string()),
        25 => Some("SMTP".to_string()),
        53 => Some("DNS".to_string()),
        80 => Some("HTTP".to_string()),
        110 => Some("POP3".to_string()),
        115 => Some("SFTP".to_string()),
        135 => Some("MS RPC".to_string()),
        139 => Some("NetBIOS".to_string()),
        143 => Some("IMAP".to_string()),
        194 => Some("IRC".to_string()),
        443 => Some("HTTPS".to_string()),
        445 => Some("SMB".to_string()),
        989 | 990 => Some("FTPS".to_string()),
        993 => Some("IMAPS".to_string()),
        995 => Some("POP3S".to_string()),
        1433 => Some("MSSQL".to_string()),
        1521 => Some("Oracle".to_string()),
        1723 => Some("PPTP".to_string()),
        3306 => Some("MySQL".to_string()),
        3389 => Some("RDP".to_string()),
        5060 => Some("SIP".to_string()),
        5432 => Some("PostgreSQL".to_string()),
        5900 => Some("VNC".to_string()),
        8080 => Some("HTTP-Proxy".to_string()),
        8443 => Some("HTTPS-Alt".to_string()),
        9090 => Some("WebConsole".to_string()),
        9100 => Some("Printer".to_string()),
        _ => None,
    }
}

async fn try_nmap_scan(target: &str, ports: &[u16]) -> Result<Vec<PortResult>, String> {
    // Check if nmap is installed
    let nmap_check = Command::new("which").arg("nmap").output();

    if nmap_check.is_err() || !nmap_check.unwrap().status.success() {
        return Err("nmap not found".to_string());
    }

    // Create port range string for nmap
    let port_str = if ports.len() <= 15 {
        // For a small number of ports, specify them individually
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(",")
    } else {
        // For many ports, just use default nmap scan
        "1-1000".to_string()
    };

    // Run nmap with XML output
    let output = Command::new("nmap")
        .args(&["-p", &port_str, "-oX", "-", target])
        .output()
        .map_err(|e| format!("Failed to execute nmap: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "nmap exited with error: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Parse the XML output
    let xml = String::from_utf8_lossy(&output.stdout);

    // Very basic XML parsing for nmap output
    let mut results = Vec::new();

    // For each port mentioned in the output
    for port in ports {
        let port_str = format!("portid=\"{}\"", port);
        let state_open = format!("<state state=\"open\"");

        // Check if this port is in the output and is open
        let port_in_output = xml.contains(&port_str);
        let is_open = port_in_output
            && xml.contains(&port_str)
            && xml[xml.find(&port_str).unwrap()..].contains(&state_open);

        // Get service information if available
        let service = if is_open {
            let port_pos = xml.find(&port_str).unwrap();
            let service_start = xml[port_pos..].find("service name=\"");

            if let Some(service_offset) = service_start {
                let service_text = &xml[port_pos + service_offset + 14..];
                let service_end = service_text.find("\"").unwrap();
                Some(service_text[..service_end].to_string())
            } else {
                None
            }
        } else {
            None
        };

        // Only include ports that were actually scanned
        if port_in_output {
            results.push(PortResult {
                number: *port,
                open: is_open,
                service,
            });
        } else {
            // Fall back to basic scan for ports not in nmap output
            // We'll handle this asynchronously below
            results.push(PortResult {
                number: *port,
                open: false,
                service: None,
            });
        }
    }

    // Handle any ports that weren't in nmap output with async fallback
    let socket_addr = match resolve_target(target) {
        Ok(addr) => addr,
        Err(_) => return Ok(results), // Just return what we have so far
    };

    // Find indices of ports that weren't in nmap output
    let mut fallback_tasks = Vec::new();
    let mut fallback_indices = Vec::new();

    for (i, result) in results.iter().enumerate() {
        if result.service.is_none() && !result.open {
            // This port wasn't properly scanned by nmap
            fallback_tasks.push(scan_port(socket_addr, result.number));
            fallback_indices.push(i);
        }
    }

    // Run fallback scans if needed
    if !fallback_tasks.is_empty() {
        let fallback_results = future::join_all(fallback_tasks).await;

        for (idx, result) in fallback_indices.into_iter().zip(fallback_results) {
            results[idx] = result;
        }
    }

    Ok(results)
}
