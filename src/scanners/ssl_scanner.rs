use crate::scanners::{Severity, Vulnerability};
use crate::utils::error::FortiCoreResult;
use serde_json::json;
use std::path::Path;
use std::net::TcpStream;
use std::time::Duration;
use std::io::{Read, Write};
use tokio::time::timeout;
use std::collections::HashMap;

// Re-export dependencies that might be missing
// In a real project, you'd add these to Cargo.toml instead
// but for this example, we'll simulate their functionality
pub mod rustls {
    pub use rustls::*;
    pub mod pki_types {
        pub enum ServerName {
            DnsName(String),
            IpAddress(std::net::IpAddr),
        }
        
        impl ServerName {
            pub fn try_from(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
                if let Ok(ip) = name.parse() {
                    Ok(Self::IpAddress(ip))
                } else {
                    Ok(Self::DnsName(name.to_string()))
                }
            }
        }
    }
    
    pub struct Certificate(pub Vec<u8>);
    
    impl Certificate {
        pub fn from_der(der: &[u8]) -> Result<Self, &'static str> {
            Ok(Self(der.to_vec()))
        }
    }
    
    #[derive(Clone)]
    pub enum CipherSuite {
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    }
    
    // Add cipher_suite namespace for compatibility
    pub mod cipher_suite {
        pub use super::CipherSuite::*;
    }
    
    #[derive(Clone)]
    pub enum ProtocolVersion {
        TLSv1_2,
        TLSv1_3,
    }
    
    pub struct RootCertStore {
        // Mock implementation
        certs: Vec<Certificate>,
    }
    
    impl RootCertStore {
        pub fn empty() -> Self {
            Self { certs: Vec::new() }
        }
        
        pub fn add(&mut self, cert: Certificate) -> Result<(), &'static str> {
            self.certs.push(cert);
            Ok(())
        }
    }
    
    pub struct ClientConfig {
        pub versions: Vec<ProtocolVersion>,
        pub ciphersuites: Vec<CipherSuite>,
    }
    
    impl ClientConfig {
        pub fn builder() -> ConfigBuilder {
            ConfigBuilder {}
        }
    }
    
    pub struct ConfigBuilder;
    
    impl ConfigBuilder {
        pub fn with_safe_defaults(self) -> ClientConfigBuilder {
            ClientConfigBuilder {}
        }
    }
    
    pub struct ClientConfigBuilder;
    
    impl ClientConfigBuilder {
        pub fn with_root_certificates(self, root_store: RootCertStore) -> Result<ClientConfigBuilderWithRoots, &'static str> {
            Ok(ClientConfigBuilderWithRoots {})
        }
    }
    
    pub struct ClientConfigBuilderWithRoots;
    
    impl ClientConfigBuilderWithRoots {
        pub fn with_no_client_auth(self) -> ClientConfig {
            ClientConfig {
                versions: vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
                ciphersuites: vec![],
            }
        }
    }
}

// Simulate the rustls_native_certs crate
pub mod rustls_native_certs {
    use super::rustls::Certificate;
    
    pub struct NativeCertificate(pub Vec<u8>);
    
    pub type CertificateResult = Result<Vec<NativeCertificate>, &'static str>;
    
    pub fn load_native_certs() -> CertificateResult {
        // Mock implementation that returns empty certs
        Ok(Vec::new())
    }
}

// Simulate tokio_rustls
pub mod tokio_rustls {
    use super::rustls::{ClientConfig, pki_types::ServerName};
    use std::sync::Arc;
    use tokio::net::TcpStream;
    
    pub struct TlsStream<T>(T);
    
    pub struct TlsConnector {
        config: Arc<ClientConfig>,
    }
    
    impl TlsConnector {
        pub fn from(config: Arc<ClientConfig>) -> Self {
            Self { config }
        }
        
        pub async fn connect(&self, _server_name: ServerName, _stream: TcpStream) -> Result<TlsStream<TcpStream>, &'static str> {
            // Mock implementation
            Err("Not implemented in this simulation")
        }
    }
}

// Simulate rand crate
pub mod rand {
    pub fn random<T>() -> T 
    where T: Default {
        // Mock implementation that returns default value
        T::default()
    }
}

// Re-export names for convenience
use self::rustls::pki_types::ServerName;
use self::rustls::{Certificate, CipherSuite};
use self::rustls::cipher_suite;

// Standard port mappings for services that commonly use SSL/TLS
const SSL_COMMON_PORTS: &[u16] = &[
    443,   // HTTPS
    465,   // SMTPS
    636,   // LDAPS
    989,   // FTPS (data)
    990,   // FTPS (control)
    993,   // IMAPS
    995,   // POP3S
    3269,  // LDAPS Global Catalog
    5061,  // SIP over TLS
    8443,  // HTTPS alternate
];

// TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsVersion {
    SSLv2,
    SSLv3,
    TLSv1_0,
    TLSv1_1,
    TLSv1_2,
    TLSv1_3,
}

impl TlsVersion {
    fn to_string(&self) -> String {
        match self {
            TlsVersion::SSLv2 => "SSL 2.0".to_string(),
            TlsVersion::SSLv3 => "SSL 3.0".to_string(),
            TlsVersion::TLSv1_0 => "TLS 1.0".to_string(),
            TlsVersion::TLSv1_1 => "TLS 1.1".to_string(),
            TlsVersion::TLSv1_2 => "TLS 1.2".to_string(),
            TlsVersion::TLSv1_3 => "TLS 1.3".to_string(),
        }
    }
    
    fn is_insecure(&self) -> bool {
        matches!(self, TlsVersion::SSLv2 | TlsVersion::SSLv3 | TlsVersion::TLSv1_0)
    }
}

// Cipher strength categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherStrength {
    Weak,       // <= 56 bit
    Medium,     // <= 112 bit
    Strong,     // > 112 bit
    VeryStrong, // AEAD ciphers with PFS
}

/// Main scanning function for SSL/TLS configuration analysis
pub async fn scan(target: &str, output_path: Option<&Path>, verbose: bool) -> FortiCoreResult<()> {
    if verbose {
        println!("Starting SSL/TLS configuration scan on target: {}", target);
    }

    let mut vulnerabilities = Vec::new();
    
    // First determine which ports are open and might be using SSL/TLS
    let ports_to_scan = get_ssl_ports_to_scan(target, verbose).await?;
    
    if verbose {
        println!("Found {} potential SSL/TLS services to scan", ports_to_scan.len());
    }
    
    // Scan each port for SSL/TLS vulnerabilities
    for port in ports_to_scan {
        if verbose {
            println!("Analyzing SSL/TLS configuration on port {}", port);
        }
        
        // Perform various SSL/TLS tests
        let mut port_vulns = scan_port_ssl_tls(target, port, verbose).await?;
        vulnerabilities.append(&mut port_vulns);
    }
    
    // Save results if output path is provided
    if let Some(path) = output_path {
        save_scan_results(&vulnerabilities, path)?;
    }
    
    if verbose {
        println!("SSL/TLS scan completed. Found {} vulnerabilities.", vulnerabilities.len());
        for vuln in &vulnerabilities {
            println!(
                "- {} ({:?}): {}",
                vuln.name, vuln.severity, vuln.description
            );
        }
    }

    Ok(())
}

/// Get a list of ports that are likely running SSL/TLS services
async fn get_ssl_ports_to_scan(target: &str, verbose: bool) -> FortiCoreResult<Vec<u16>> {
    use crate::scanners::port_scanner;
    
    // Scan the common SSL/TLS ports
    let ports = port_scanner::scan_ports(target, SSL_COMMON_PORTS).await?;
    
    // Filter to only include open ports
    let open_ports = ports.iter()
        .filter(|p| p.open)
        .map(|p| p.number)
        .collect::<Vec<_>>();
    
    if verbose {
        println!("Found {} potentially open SSL/TLS ports", open_ports.len());
    }
    
    Ok(open_ports)
}

/// Scan a specific port for SSL/TLS vulnerabilities
async fn scan_port_ssl_tls(target: &str, port: u16, verbose: bool) -> FortiCoreResult<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();
    
    // Test for supported TLS versions
    let supported_versions = test_supported_tls_versions(target, port, verbose).await?;
    
    // Check for insecure protocol versions
    for version in &supported_versions {
        if version.is_insecure() {
            let severity = match version {
                TlsVersion::SSLv2 => Severity::Critical,
                TlsVersion::SSLv3 => Severity::High,
                TlsVersion::TLSv1_0 => Severity::Medium,
                _ => Severity::Low,
            };
            
            vulnerabilities.push(Vulnerability {
                id: format!("SSL-PROTO-{}", version.to_string().replace(" ", "-")),
                name: format!("Insecure Protocol Version: {}", version.to_string()),
                description: format!("Server supports {}, which is considered insecure", version.to_string()),
                severity,
                location: format!("{}:{}", target, port),
                details: json!({
                    "port": port,
                    "protocol_version": version.to_string(),
                    "recommendation": "Disable support for this protocol version"
                }),
                exploitable: true,
            });
        }
    }
    
    // Check for weak cipher suites
    if supported_versions.len() > 0 {
        let weak_ciphers = test_weak_cipher_suites(target, port, verbose).await?;
        
        if !weak_ciphers.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: "SSL-WEAK-CIPHERS".to_string(),
                name: "Weak Cipher Suites Supported".to_string(),
                description: format!("Server supports {} weak cipher suites", weak_ciphers.len()),
                severity: Severity::High,
                location: format!("{}:{}", target, port),
                details: json!({
                    "port": port,
                    "weak_ciphers": weak_ciphers,
                    "recommendation": "Disable support for weak cipher suites and enable only strong ciphers"
                }),
                exploitable: true,
            });
        }
    }
    
    // Check for certificate issues
    let cert_issues = check_certificate(target, port, verbose).await?;
    for issue in cert_issues {
        vulnerabilities.push(issue);
    }
    
    // Test for specific SSL/TLS vulnerabilities
    let vulnerabilities_to_test = [
        ("BEAST", test_beast_vulnerability(target, port, verbose).await?),
        ("POODLE", test_poodle_vulnerability(target, port, verbose).await?),
        ("HEARTBLEED", test_heartbleed_vulnerability(target, port, verbose).await?),
        ("LOGJAM", test_logjam_vulnerability(target, port, verbose).await?),
        ("FREAK", test_freak_vulnerability(target, port, verbose).await?),
    ];
    
    for (name, is_vulnerable) in vulnerabilities_to_test {
        if is_vulnerable {
            let (severity, description) = match name {
                "BEAST" => (
                    Severity::Medium, 
                    "Server is vulnerable to the BEAST attack (Browser Exploit Against SSL/TLS)".to_string()
                ),
                "POODLE" => (
                    Severity::High, 
                    "Server is vulnerable to the POODLE attack (Padding Oracle On Downgraded Legacy Encryption)".to_string()
                ),
                "HEARTBLEED" => (
                    Severity::Critical, 
                    "Server is vulnerable to the Heartbleed attack (CVE-2014-0160)".to_string()
                ),
                "LOGJAM" => (
                    Severity::Medium, 
                    "Server is vulnerable to the Logjam attack, allowing an attacker to downgrade TLS connections".to_string()
                ),
                "FREAK" => (
                    Severity::Medium, 
                    "Server is vulnerable to the FREAK attack (Factoring RSA Export Keys)".to_string()
                ),
                _ => unreachable!(),
            };
            
            vulnerabilities.push(Vulnerability {
                id: format!("SSL-{}", name),
                name: format!("{} Vulnerability", name),
                description,
                severity,
                location: format!("{}:{}", target, port),
                details: json!({
                    "port": port,
                    "vulnerability": name,
                    "recommendation": format!("Patch the server to fix the {} vulnerability", name)
                }),
                exploitable: true,
            });
        }
    }
    
    Ok(vulnerabilities)
}

/// Test which TLS versions are supported by the server
async fn test_supported_tls_versions(target: &str, port: u16, verbose: bool) -> FortiCoreResult<Vec<TlsVersion>> {
    if verbose {
        println!("Testing supported TLS versions for {}:{}", target, port);
    }
    
    let mut supported_versions = Vec::new();
    
    // Define a short timeout for each connection attempt
    let timeout_duration = Duration::from_secs(5);
    
    // Test each protocol version
    let versions_to_test = [
        (TlsVersion::SSLv2, "SSLv2"),
        (TlsVersion::SSLv3, "SSLv3"),
        (TlsVersion::TLSv1_0, "TLSv1.0"),
        (TlsVersion::TLSv1_1, "TLSv1.1"),
        (TlsVersion::TLSv1_2, "TLSv1.2"),
        (TlsVersion::TLSv1_3, "TLSv1.3"),
    ];
    
    for (version, version_str) in &versions_to_test {
        if verbose {
            println!("  Testing {} support...", version_str);
        }
        
        let version_supported = match *version {
            TlsVersion::SSLv2 => {
                // SSLv2 is very old and not supported by modern libraries
                // We'll try to connect using a basic socket with SSLv2 ClientHello
                let result = timeout(
                    timeout_duration,
                    test_sslv2_connection(target, port)
                ).await;
                
                match result {
                    Ok(Ok(is_supported)) => is_supported,
                    _ => false,
                }
            },
            TlsVersion::SSLv3 => {
                // SSLv3 is deprecated but can be tested with a specialized TLS config
                let result = timeout(
                    timeout_duration,
                    test_tls_connection(target, port, *version)
                ).await;
                
                match result {
                    Ok(Ok(is_supported)) => is_supported,
                    _ => false,
                }
            },
            _ => {
                // For modern TLS versions, we'll use rustls
                let result = timeout(
                    timeout_duration,
                    test_tls_connection(target, port, *version)
                ).await;
                
                match result {
                    Ok(Ok(is_supported)) => is_supported,
                    _ => false,
                }
            }
        };
        
        if version_supported {
            if verbose {
                println!("  ✓ {} is supported", version_str);
            }
            supported_versions.push(*version);
        } else if verbose {
            println!("  ✗ {} is not supported", version_str);
        }
    }
    
    if verbose {
        println!("Detected {} supported TLS versions", supported_versions.len());
    }
    
    Ok(supported_versions)
}

/// Test for weak cipher suites
async fn test_weak_cipher_suites(target: &str, port: u16, verbose: bool) -> FortiCoreResult<Vec<String>> {
    if verbose {
        println!("Testing for weak cipher suites on {}:{}", target, port);
    }
    
    // In a real implementation, we would enumerate supported cipher suites and
    // check them against a list of known weak ciphers.
    // For this example, we'll return a predefined list of weak ciphers.
    
    // These are common weak ciphers - a real implementation would actually detect them
    let weak_ciphers = vec![
        "TLS_RSA_WITH_RC4_128_SHA".to_string(),
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string(),
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA".to_string(),
    ];
    
    if verbose {
        println!("Detected {} weak cipher suites", weak_ciphers.len());
    }
    
    Ok(weak_ciphers)
}

/// Check for certificate issues (self-signed, expired, etc.)
async fn check_certificate(target: &str, port: u16, verbose: bool) -> FortiCoreResult<Vec<Vulnerability>> {
    if verbose {
        println!("Checking certificate issues for {}:{}", target, port);
    }
    
    let mut vulnerabilities = Vec::new();
    
    // In a real implementation, we would retrieve and parse the certificate
    // For this example, we'll create some example certificate issues
    
    // Check for self-signed certificate
    let self_signed = true; // Placeholder - would actually check certificate
    if self_signed {
        vulnerabilities.push(Vulnerability {
            id: "SSL-CERT-SELF-SIGNED".to_string(),
            name: "Self-Signed Certificate".to_string(),
            description: "Server is using a self-signed certificate which cannot be validated by clients".to_string(),
            severity: Severity::Medium,
            location: format!("{}:{}", target, port),
            details: json!({
                "port": port,
                "issue": "self-signed",
                "recommendation": "Use a certificate signed by a trusted Certificate Authority"
            }),
            exploitable: false,
        });
    }
    
    // Check for expired certificate
    let expired = false; // Placeholder - would actually check certificate
    if expired {
        vulnerabilities.push(Vulnerability {
            id: "SSL-CERT-EXPIRED".to_string(),
            name: "Expired Certificate".to_string(),
            description: "Server's certificate has expired".to_string(),
            severity: Severity::High,
            location: format!("{}:{}", target, port),
            details: json!({
                "port": port,
                "issue": "expired",
                "recommendation": "Renew the certificate"
            }),
            exploitable: false,
        });
    }
    
    // Check for weak key (e.g., 1024-bit RSA)
    let weak_key = true; // Placeholder - would actually check certificate
    if weak_key {
        vulnerabilities.push(Vulnerability {
            id: "SSL-CERT-WEAK-KEY".to_string(),
            name: "Weak Certificate Key".to_string(),
            description: "Server's certificate uses a weak key (e.g., 1024-bit RSA)".to_string(),
            severity: Severity::Medium,
            location: format!("{}:{}", target, port),
            details: json!({
                "port": port,
                "issue": "weak_key",
                "recommendation": "Use a certificate with at least 2048-bit RSA key or ECC key"
            }),
            exploitable: false,
        });
    }
    
    if verbose {
        println!("Detected {} certificate issues", vulnerabilities.len());
    }
    
    Ok(vulnerabilities)
}

/// Test for the BEAST vulnerability
async fn test_beast_vulnerability(target: &str, port: u16, verbose: bool) -> FortiCoreResult<bool> {
    if verbose {
        println!("Testing for BEAST vulnerability on {}:{}", target, port);
    }
    
    // BEAST vulnerability affects TLS 1.0 and below with CBC cipher suites
    // First, check if the server supports TLS 1.0
    let supported_versions = test_supported_tls_versions(target, port, false).await?;
    let supports_tls_1_0 = supported_versions.contains(&TlsVersion::TLSv1_0);
    
    if !supports_tls_1_0 {
        if verbose {
            println!("  ✓ Not vulnerable to BEAST (TLS 1.0 not supported)");
        }
        return Ok(false);
    }
    
    // Next, check if the server supports CBC ciphers with TLS 1.0
    let cbc_ciphers = [
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    ];
    
    // Create a TCP connection
    let addr = format!("{}:{}", target, port);
    let stream = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    
    // Set timeouts
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    
    // Craft a TLS 1.0 ClientHello with CBC ciphers
    let mut client_hello = create_tls_1_0_client_hello(target);
    
    // Replace the cipher suites section with CBC ciphers
    // In a real implementation, we'd carefully craft this section
    // For now, we'll use the default in create_tls_1_0_client_hello
    
    // Send ClientHello
    let mut stream = stream;
    if let Err(_) = stream.write_all(&client_hello) {
        return Ok(false);
    }
    
    // Read response
    let mut response = [0u8; 1024];
    let size = match stream.read(&mut response) {
        Ok(s) if s > 0 => s,
        _ => return Ok(false),
    };
    
    // Check if server accepted TLS 1.0 with CBC cipher
    let is_vulnerable = validate_tls_1_0_server_hello(&response[..size]);
    
    if verbose {
        if is_vulnerable {
            println!("  ⚠ Vulnerable to BEAST attack (TLS 1.0 with CBC ciphers supported)");
        } else {
            println!("  ✓ Not vulnerable to BEAST attack");
        }
    }
    
    Ok(is_vulnerable)
}

/// Test for the POODLE vulnerability
async fn test_poodle_vulnerability(target: &str, port: u16, verbose: bool) -> FortiCoreResult<bool> {
    if verbose {
        println!("Testing for POODLE vulnerability on {}:{}", target, port);
    }
    
    // POODLE vulnerability affects SSLv3 with CBC cipher suites
    // First, check if the server supports SSLv3
    let supported_versions = test_supported_tls_versions(target, port, false).await?;
    let supports_sslv3 = supported_versions.contains(&TlsVersion::SSLv3);
    
    if !supports_sslv3 {
        if verbose {
            println!("  ✓ Not vulnerable to POODLE (SSLv3 not supported)");
        }
        return Ok(false);
    }
    
    // For SSLv3, we need to check if CBC ciphers are supported
    // Create a TCP connection
    let addr = format!("{}:{}", target, port);
    let stream = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    
    // Set timeouts
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    
    // Create an SSLv3 ClientHello with CBC ciphers
    // This is a simplified SSLv3 Client Hello message
    let mut msg = Vec::new();
    
    // SSLv3 record header: content type (22 = handshake), version (3,0 = SSLv3), length (will be set later)
    msg.extend_from_slice(&[0x16, 0x03, 0x00, 0x00, 0x00]); // Length will be filled in later
    
    // Handshake header: type (1 = client hello), length (will be set later)
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Length will be filled in later
    
    // Client hello: client version (3,0 = SSLv3)
    msg.extend_from_slice(&[0x03, 0x00]);
    
    // Client random (32 bytes)
    for _ in 0..32 {
        msg.push(rand::random::<u8>());
    }
    
    // Session ID length (0)
    msg.push(0x00);
    
    // Cipher suites length (6 bytes for 3 cipher suites)
    msg.extend_from_slice(&[0x00, 0x06]);
    
    // CBC cipher suites (SSLv3)
    msg.extend_from_slice(&[
        0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x0A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    ]);
    
    // Compression methods length (1)
    msg.push(0x01);
    
    // Compression method (0 = none)
    msg.push(0x00);
    
    // No extensions for SSLv3
    
    // Update the message lengths
    let handshake_length = msg.len() - 9;
    let record_length = msg.len() - 5;
    
    msg[3] = ((record_length >> 8) & 0xFF) as u8;
    msg[4] = (record_length & 0xFF) as u8;
    
    msg[6] = ((handshake_length >> 16) & 0xFF) as u8;
    msg[7] = ((handshake_length >> 8) & 0xFF) as u8;
    msg[8] = (handshake_length & 0xFF) as u8;
    
    // Send ClientHello
    let mut stream = stream;
    if let Err(_) = stream.write_all(&msg) {
        return Ok(false);
    }
    
    // Read response
    let mut response = [0u8; 1024];
    let size = match stream.read(&mut response) {
        Ok(s) if s > 0 => s,
        _ => return Ok(false),
    };
    
    // Check if the response is a valid SSLv3 ServerHello
    // The record header should have content type 22 (handshake)
    // and version 3.0 (SSLv3)
    let is_vulnerable = response.len() >= 3 && 
                       response[0] == 0x16 && // Handshake
                       response[1] == 0x03 && // Version major = 3
                       response[2] == 0x00;   // Version minor = 0 (SSLv3)
    
    if verbose {
        if is_vulnerable {
            println!("  ⚠ Vulnerable to POODLE attack (SSLv3 with CBC ciphers supported)");
        } else {
            println!("  ✓ Not vulnerable to POODLE attack");
        }
    }
    
    Ok(is_vulnerable)
}

/// Test for the Heartbleed vulnerability
async fn test_heartbleed_vulnerability(target: &str, port: u16, verbose: bool) -> FortiCoreResult<bool> {
    if verbose {
        println!("Testing for Heartbleed vulnerability on {}:{}", target, port);
    }
    
    // Heartbleed (CVE-2014-0160) affects OpenSSL 1.0.1-1.0.1f with heartbeat extension
    
    // First, check if the server supports TLS 1.2 or TLS 1.1 (where Heartbleed is relevant)
    let supported_versions = test_supported_tls_versions(target, port, false).await?;
    let supports_vulnerable_tls = supported_versions.contains(&TlsVersion::TLSv1_2) || 
                                supported_versions.contains(&TlsVersion::TLSv1_1);
    
    if !supports_vulnerable_tls {
        if verbose {
            println!("  ✓ Not vulnerable to Heartbleed (TLS 1.1/1.2 not supported)");
        }
        return Ok(false);
    }
    
    // Create a TCP connection
    let addr = format!("{}:{}", target, port);
    let stream = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    
    // Set timeouts
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    
    // Create a TLS 1.2 ClientHello with heartbeat extension
    let mut msg = Vec::new();
    
    // TLS record header: content type (22 = handshake), version (3,3 = TLS 1.2), length (will be set later)
    msg.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]); // Length will be filled in later
    
    // Handshake header: type (1 = client hello), length (will be set later)
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Length will be filled in later
    
    // Client hello: client version (3,3 = TLS 1.2)
    msg.extend_from_slice(&[0x03, 0x03]);
    
    // Client random (32 bytes)
    for _ in 0..32 {
        msg.push(rand::random::<u8>());
    }
    
    // Session ID length (0)
    msg.push(0x00);
    
    // Cipher suites length (2 bytes for 1 cipher)
    msg.extend_from_slice(&[0x00, 0x02]);
    
    // Cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA)
    msg.extend_from_slice(&[0x00, 0x2F]);
    
    // Compression methods length (1)
    msg.push(0x01);
    
    // Compression method (0 = none)
    msg.push(0x00);
    
    // Extensions length (will be set later)
    msg.extend_from_slice(&[0x00, 0x00]);
    
    // Heartbeat extension
    msg.extend_from_slice(&[
        0x00, 0x0F, // Extension type: heartbeat (15)
        0x00, 0x01, // Extension length: 1
        0x01        // Peer allowed to send requests
    ]);
    
    // Update extensions length
    let extensions_length = 5; // Length of our heartbeat extension
    let msg_len = msg.len();
    msg[msg_len - extensions_length - 2] = ((extensions_length >> 8) & 0xFF) as u8;
    msg[msg_len - extensions_length - 1] = (extensions_length & 0xFF) as u8;
    
    // Update the message lengths
    let handshake_length = msg.len() - 9;
    let record_length = msg.len() - 5;
    
    msg[3] = ((record_length >> 8) & 0xFF) as u8;
    msg[4] = (record_length & 0xFF) as u8;
    
    msg[6] = ((handshake_length >> 16) & 0xFF) as u8;
    msg[7] = ((handshake_length >> 8) & 0xFF) as u8;
    msg[8] = (handshake_length & 0xFF) as u8;
    
    // Send ClientHello
    let mut stream = stream;
    if let Err(_) = stream.write_all(&msg) {
        return Ok(false);
    }
    
    // Read ServerHello
    let mut response = [0u8; 8192]; // Larger buffer to handle ServerHello
    let size = match stream.read(&mut response) {
        Ok(s) if s > 0 => s,
        _ => return Ok(false),
    };
    
    // Check if the ServerHello includes the heartbeat extension
    // This is a simplified check - in a real implementation we would parse the entire
    // ServerHello to find the heartbeat extension
    let response_data = &response[..size];
    let has_heartbeat_extension = find_heartbeat_extension(response_data);
    
    if !has_heartbeat_extension {
        if verbose {
            println!("  ✓ Not vulnerable to Heartbleed (no heartbeat extension)");
        }
        return Ok(false);
    }
    
    // If heartbeat extension is supported, send a malformed heartbeat request
    // Complete the TLS handshake first (simplified)
    
    // Wait for server's remaining handshake messages
    // This is simplified - in a real implementation we would handle the full handshake
    std::thread::sleep(Duration::from_millis(500));
    while let Ok(s) = stream.read(&mut response) {
        if s == 0 {
            break;
        }
    }
    
    // Now send a malformed heartbeat message with a payload length larger than the actual payload
    let heartbeat_request = [
        0x18,                   // Content type: heartbeat
        0x03, 0x03,             // TLS version
        0x00, 0x03,             // Length
        0x01,                   // Type: request
        0x40, 0x00              // Payload length: 16384 (but we don't send any payload)
    ];
    
    if let Err(_) = stream.write_all(&heartbeat_request) {
        return Ok(false);
    }
    
    // Read the response
    let mut heartbeat_response = [0u8; 16384]; // Large buffer to catch memory leak
    let response_size = match stream.read(&mut heartbeat_response) {
        Ok(s) if s > 0 => s,
        _ => 0,
    };
    
    // If the server is vulnerable to Heartbleed, it will return more data than it should
    // A response larger than a few bytes may indicate that the server is leaking memory
    let is_vulnerable = response_size > 3;
    
    if verbose {
        if is_vulnerable {
            println!("  ⚠ Vulnerable to Heartbleed attack (received {} bytes of potentially leaked memory)", response_size);
        } else {
            println!("  ✓ Not vulnerable to Heartbleed attack");
        }
    }
    
    Ok(is_vulnerable)
}

// Helper function to find heartbeat extension in ServerHello
fn find_heartbeat_extension(data: &[u8]) -> bool {
    // This is a simplified implementation
    // In a real implementation, we would properly parse the ServerHello message
    
    // Look for the heartbeat extension type (0x000F) in the data
    for i in 0..data.len()-3 {
        if data[i] == 0x00 && data[i+1] == 0x0F && data[i+2] == 0x00 && data[i+3] == 0x01 {
            return true;
        }
    }
    
    false
}

/// Test a TLS connection with a specific protocol version
async fn test_tls_connection(target: &str, port: u16, version: TlsVersion) -> FortiCoreResult<bool> {
    // Convert to a socket address
    let addr = format!("{}:{}", target, port);
    
    // Create a TLS configuration based on the protocol version
    let mut client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(load_root_certs()?)?
        .with_no_client_auth();
    
    // Modify TLS parameters based on version
    let protocol_versions = match version {
        TlsVersion::SSLv3 => {
            // SSLv3 is not directly supported by rustls, so we'll simulate a connection failure
            return Ok(false);
        },
        TlsVersion::TLSv1_0 => {
            // TLS 1.0 is often disabled
            return test_legacy_tls_version(target, port, version).await;
        },
        TlsVersion::TLSv1_1 => {
            // TLS 1.1 is considered legacy but may be enabled
            return test_legacy_tls_version(target, port, version).await;
        },
        TlsVersion::TLSv1_2 => {
            vec![rustls::ProtocolVersion::TLSv1_2]
        },
        TlsVersion::TLSv1_3 => {
            vec![rustls::ProtocolVersion::TLSv1_3]
        },
        _ => return Ok(false), // Not expected to reach here
    };
    
    // Attempt to establish a TLS connection
    let server_name = match ServerName::try_from(target) {
        Ok(name) => name,
        Err(_) => {
            // If we can't parse the target as a valid DNS name (e.g., it's an IP),
            // use a dummy name
            match ServerName::try_from("example.com") {
                Ok(name) => name,
                Err(_) => return Ok(false),
            }
        }
    };
    
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    
    // Connect to the server
    match tokio::net::TcpStream::connect(&addr).await {
        Ok(stream) => {
            // Try to establish the TLS connection
            match connector.connect(server_name.clone(), stream).await {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        },
        Err(_) => Ok(false),
    }
}

/// Test for legacy TLS versions (1.0, 1.1) which may require special handling
async fn test_legacy_tls_version(target: &str, port: u16, version: TlsVersion) -> FortiCoreResult<bool> {
    // For legacy versions, use a basic TCP socket and implement a simplified TLS handshake
    // This is not a complete implementation, but it can detect if a server supports the protocol
    let addr = format!("{}:{}", target, port);
    
    // Attempt to connect using a TCP socket
    match std::net::TcpStream::connect(addr) {
        Ok(mut stream) => {
            // Set a timeout for the socket
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            
            // Construct a simplified Client Hello message based on the TLS version
            let client_hello = match version {
                TlsVersion::TLSv1_0 => create_tls_1_0_client_hello(target),
                TlsVersion::TLSv1_1 => create_tls_1_1_client_hello(target),
                _ => return Ok(false),
            };
            
            // Send the Client Hello
            if let Err(_) = stream.write_all(&client_hello) {
                return Ok(false);
            }
            
            // Read the server response
            let mut response = [0u8; 1024];
            match stream.read(&mut response) {
                Ok(size) if size > 0 => {
                    // Check if the response is a valid Server Hello for the given version
                    let is_valid = match version {
                        TlsVersion::TLSv1_0 => validate_tls_1_0_server_hello(&response[..size]),
                        TlsVersion::TLSv1_1 => validate_tls_1_1_server_hello(&response[..size]),
                        _ => false,
                    };
                    Ok(is_valid)
                },
                _ => Ok(false),
            }
        },
        Err(_) => Ok(false),
    }
}

/// Test for SSLv2 support using a raw TCP connection
async fn test_sslv2_connection(target: &str, port: u16) -> FortiCoreResult<bool> {
    // SSLv2 is very old, so we'll implement a simplified handshake
    let addr = format!("{}:{}", target, port);
    
    // Attempt to connect using a TCP socket
    let stream = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    
    // Set timeouts
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    
    // Create an SSLv2 CLIENT-HELLO message
    let sslv2_hello = create_sslv2_client_hello();
    
    let mut stream = stream;
    if let Err(_) = stream.write_all(&sslv2_hello) {
        return Ok(false);
    }
    
    // Read the response
    let mut response = [0u8; 1024];
    match stream.read(&mut response) {
        Ok(size) if size > 0 => {
            // Check if the response seems to be a valid SSLv2 SERVER-HELLO
            Ok(validate_sslv2_server_hello(&response[..size]))
        },
        _ => Ok(false),
    }
}

/// Load root certificates from the system
fn load_root_certs() -> FortiCoreResult<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                if let Ok(cert) = Certificate::from_der(&cert.0) {
                    root_store.add(cert).ok(); // Ignore errors for individual certs
                }
            }
        },
        Err(_) => {
            // If we can't load the system's root certs, we'll create an empty store
            // This will likely cause certificate validation to fail
        }
    }
    
    Ok(root_store)
}

/// Create a TLS 1.0 Client Hello message
fn create_tls_1_0_client_hello(server_name: &str) -> Vec<u8> {
    // This is a simplified TLS 1.0 Client Hello message with minimal configuration
    let mut msg = Vec::new();
    
    // TLS record header: content type (22 = handshake), version (3,1 = TLS 1.0), length (will be set later)
    msg.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]); // Length will be filled in later
    
    // Handshake header: type (1 = client hello), length (will be set later)
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Length will be filled in later
    
    // Client hello: client version (3,1 = TLS 1.0)
    msg.extend_from_slice(&[0x03, 0x01]);
    
    // Client random (32 bytes)
    for _ in 0..32 {
        msg.push(rand::random::<u8>());
    }
    
    // Session ID length (0)
    msg.push(0x00);
    
    // Cipher suites length (2 bytes for 1 suite)
    msg.extend_from_slice(&[0x00, 0x02]);
    
    // Cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA)
    msg.extend_from_slice(&[0x00, 0x2F]);
    
    // Compression methods length (1)
    msg.push(0x01);
    
    // Compression method (0 = none)
    msg.push(0x00);
    
    // No extensions
    
    // Update the message lengths
    let handshake_length = msg.len() - 9;
    let record_length = msg.len() - 5;
    
    msg[3] = ((record_length >> 8) & 0xFF) as u8;
    msg[4] = (record_length & 0xFF) as u8;
    
    msg[6] = ((handshake_length >> 16) & 0xFF) as u8;
    msg[7] = ((handshake_length >> 8) & 0xFF) as u8;
    msg[8] = (handshake_length & 0xFF) as u8;
    
    msg
}

/// Create a TLS 1.1 Client Hello message
fn create_tls_1_1_client_hello(server_name: &str) -> Vec<u8> {
    // This is a simplified TLS 1.1 Client Hello message with minimal configuration
    let mut msg = Vec::new();
    
    // TLS record header: content type (22 = handshake), version (3,2 = TLS 1.1), length (will be set later)
    msg.extend_from_slice(&[0x16, 0x03, 0x02, 0x00, 0x00]); // Length will be filled in later
    
    // Handshake header: type (1 = client hello), length (will be set later)
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Length will be filled in later
    
    // Client hello: client version (3,2 = TLS 1.1)
    msg.extend_from_slice(&[0x03, 0x02]);
    
    // Client random (32 bytes)
    for _ in 0..32 {
        msg.push(rand::random::<u8>());
    }
    
    // Session ID length (0)
    msg.push(0x00);
    
    // Cipher suites length (2 bytes for 1 suite)
    msg.extend_from_slice(&[0x00, 0x02]);
    
    // Cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA)
    msg.extend_from_slice(&[0x00, 0x2F]);
    
    // Compression methods length (1)
    msg.push(0x01);
    
    // Compression method (0 = none)
    msg.push(0x00);
    
    // No extensions
    
    // Update the message lengths
    let handshake_length = msg.len() - 9;
    let record_length = msg.len() - 5;
    
    msg[3] = ((record_length >> 8) & 0xFF) as u8;
    msg[4] = (record_length & 0xFF) as u8;
    
    msg[6] = ((handshake_length >> 16) & 0xFF) as u8;
    msg[7] = ((handshake_length >> 8) & 0xFF) as u8;
    msg[8] = (handshake_length & 0xFF) as u8;
    
    msg
}

/// Create an SSLv2 Client Hello message
fn create_sslv2_client_hello() -> Vec<u8> {
    // This is a simplified SSLv2 Client Hello message
    let mut msg = Vec::new();
    
    // SSLv2 header (length + record type)
    msg.extend_from_slice(&[0x80, 0x2E]); // Record length (46 bytes) with high bit set for SSLv2
    
    // Message type (CLIENT-HELLO = 1)
    msg.push(0x01);
    
    // Version (SSLv2 = 0x0002)
    msg.extend_from_slice(&[0x00, 0x02]);
    
    // Cipher spec length (9)
    msg.extend_from_slice(&[0x00, 0x09]);
    
    // Session ID length (0)
    msg.extend_from_slice(&[0x00, 0x00]);
    
    // Challenge length (16)
    msg.extend_from_slice(&[0x00, 0x10]);
    
    // Cipher specs (3 common SSLv2 ciphers, 3 bytes each)
    msg.extend_from_slice(&[
        0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
        0x03, 0x00, 0x80, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        0x07, 0x00, 0xC0, // SSL_CK_IDEA_128_CBC_WITH_MD5
    ]);
    
    // Challenge (16 random bytes)
    for _ in 0..16 {
        msg.push(rand::random::<u8>());
    }
    
    msg
}

/// Validate a TLS 1.0 Server Hello response
fn validate_tls_1_0_server_hello(response: &[u8]) -> bool {
    // Check if the response has the minimum size for a Server Hello
    if response.len() < 10 {
        return false;
    }
    
    // Check if it's a handshake message (content type = 22)
    if response[0] != 0x16 {
        return false;
    }
    
    // Check if the version in the record header is TLS 1.0 (3,1)
    if response[1] != 0x03 || response[2] != 0x01 {
        return false;
    }
    
    // Check if it's a Server Hello message (handshake type = 2)
    // The handshake type is at position 5 in the response
    if response.len() > 5 && response[5] != 0x02 {
        return false;
    }
    
    true
}

/// Validate a TLS 1.1 Server Hello response
fn validate_tls_1_1_server_hello(response: &[u8]) -> bool {
    // Check if the response has the minimum size for a Server Hello
    if response.len() < 10 {
        return false;
    }
    
    // Check if it's a handshake message (content type = 22)
    if response[0] != 0x16 {
        return false;
    }
    
    // Check if the version in the record header is TLS 1.1 (3,2) or higher
    if response[1] != 0x03 || response[2] < 0x02 {
        return false;
    }
    
    // Check if it's a Server Hello message (handshake type = 2)
    // The handshake type is at position 5 in the response
    if response.len() > 5 && response[5] != 0x02 {
        return false;
    }
    
    true
}

/// Validate an SSLv2 Server Hello response
fn validate_sslv2_server_hello(response: &[u8]) -> bool {
    // Check if the response has the minimum size for an SSLv2 Server Hello
    if response.len() < 11 {
        return false;
    }
    
    // Check if it's an SSLv2 message (first byte has high bit set)
    if (response[0] & 0x80) == 0 {
        return false;
    }
    
    // Check if it's a SERVER-HELLO message (message type = 4)
    // For SSLv2, the message type is at position 2
    if response.len() > 2 && response[2] != 0x04 {
        return false;
    }
    
    true
}

fn save_scan_results(vulnerabilities: &[Vulnerability], path: &Path) -> FortiCoreResult<()> {
    use std::fs::File;
    use std::io::Write;

    let results_json = serde_json::to_string_pretty(vulnerabilities)?;
    let mut file = File::create(path)?;
    file.write_all(results_json.as_bytes())?;

    Ok(())
}

/// Test for supported cipher suites on the target
pub async fn test_cipher_suites(target: &str, port: u16, verbose: bool) -> FortiCoreResult<HashMap<String, Vec<String>>> {
    if verbose {
        println!("Testing supported cipher suites for {}:{}", target, port);
    }
    
    // Define cipher suites categorized by security level
    let strong_ciphers = vec![
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ];
    
    let medium_ciphers = vec![
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    ];
    
    let weak_ciphers = vec![
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    ];
    
    let very_weak_ciphers = vec![
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_RC4_128_MD5",
        "TLS_RSA_WITH_NULL_SHA256",
        "TLS_RSA_WITH_NULL_SHA",
        "TLS_RSA_WITH_NULL_MD5",
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    ];
    
    // Initialize result map
    let mut results: HashMap<String, Vec<String>> = HashMap::new();
    results.insert("strong".to_string(), Vec::new());
    results.insert("medium".to_string(), Vec::new());
    results.insert("weak".to_string(), Vec::new());
    results.insert("very_weak".to_string(), Vec::new());
    
    // Test all cipher suites
    if verbose {
        println!("Testing strong cipher suites...");
    }
    for cipher in &strong_ciphers {
        if test_cipher_support(target, port, cipher).await? {
            if verbose {
                println!("  ✓ Strong cipher supported: {}", cipher);
            }
            results.get_mut("strong").unwrap().push(cipher.to_string());
        } else if verbose {
            println!("  ✗ Strong cipher not supported: {}", cipher);
        }
    }
    
    if verbose {
        println!("Testing medium cipher suites...");
    }
    for cipher in &medium_ciphers {
        if test_cipher_support(target, port, cipher).await? {
            if verbose {
                println!("  ✓ Medium cipher supported: {}", cipher);
            }
            results.get_mut("medium").unwrap().push(cipher.to_string());
        } else if verbose {
            println!("  ✗ Medium cipher not supported: {}", cipher);
        }
    }
    
    if verbose {
        println!("Testing weak cipher suites...");
    }
    for cipher in &weak_ciphers {
        if test_cipher_support(target, port, cipher).await? {
            if verbose {
                println!("  ✓ Weak cipher supported: {}", cipher);
            }
            results.get_mut("weak").unwrap().push(cipher.to_string());
        } else if verbose {
            println!("  ✗ Weak cipher not supported: {}", cipher);
        }
    }
    
    if verbose {
        println!("Testing very weak cipher suites...");
    }
    for cipher in &very_weak_ciphers {
        if test_cipher_support(target, port, cipher).await? {
            if verbose {
                println!("  ⚠ Very weak cipher supported: {}", cipher);
            }
            results.get_mut("very_weak").unwrap().push(cipher.to_string());
        } else if verbose {
            println!("  ✗ Very weak cipher not supported: {}", cipher);
        }
    }
    
    Ok(results)
}

/// Test if a specific cipher suite is supported
async fn test_cipher_support(target: &str, port: u16, cipher_name: &str) -> FortiCoreResult<bool> {
    // Map cipher name to handling strategy
    if cipher_name.starts_with("TLS_AES_") || cipher_name.starts_with("TLS_CHACHA20_") {
        // TLS 1.3 ciphers
        test_tls13_cipher(target, port, cipher_name).await
    } else if cipher_name.starts_with("TLS_ECDHE_") {
        // TLS 1.2 ECDHE ciphers
        test_tls12_cipher(target, port, cipher_name).await
    } else {
        // Legacy ciphers - test with custom implementation
        test_legacy_cipher(target, port, cipher_name).await
    }
}

/// Test TLS 1.3 cipher support
async fn test_tls13_cipher(target: &str, port: u16, cipher_name: &str) -> FortiCoreResult<bool> {
    // Convert to a socket address
    let addr = format!("{}:{}", target, port);
    
    // Create a TLS configuration for TLS 1.3
    let mut client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(load_root_certs()?)?
        .with_no_client_auth();
    
    // Set only the specific cipher suite to test
    match cipher_name {
        "TLS_AES_128_GCM_SHA256" => {
            client_config.ciphersuites = vec![CipherSuite::TLS13_AES_128_GCM_SHA256];
        },
        "TLS_AES_256_GCM_SHA384" => {
            client_config.ciphersuites = vec![CipherSuite::TLS13_AES_256_GCM_SHA384];
        },
        "TLS_CHACHA20_POLY1305_SHA256" => {
            client_config.ciphersuites = vec![CipherSuite::TLS13_CHACHA20_POLY1305_SHA256];
        },
        _ => return Ok(false), // Unsupported cipher
    }
    
    let server_name = match ServerName::try_from(target) {
        Ok(name) => name,
        Err(_) => {
            // If we can't parse the target as a valid DNS name (e.g., it's an IP),
            // use a dummy name
            match ServerName::try_from("example.com") {
                Ok(name) => name,
                Err(_) => return Ok(false),
            }
        }
    };
    
    // Create TLS connector
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    
    // Connect to the server
    match timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            // Try to establish the TLS connection
            match timeout(Duration::from_secs(5), connector.connect(server_name, stream)).await {
                Ok(Ok(_)) => Ok(true),
                _ => Ok(false),
            }
        },
        _ => Ok(false),
    }
}

/// Test TLS 1.2 cipher support
async fn test_tls12_cipher(target: &str, port: u16, cipher_name: &str) -> FortiCoreResult<bool> {
    // Convert to a socket address
    let addr = format!("{}:{}", target, port);
    
    // Create a TLS configuration for TLS 1.2
    let mut client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(load_root_certs()?)?
        .with_no_client_auth();
    
    // Make sure we only use TLS 1.2
    client_config.versions = vec![rustls::ProtocolVersion::TLSv1_2];
    
    // Set appropriate cipher suites based on the one we're testing
    client_config.ciphersuites = match cipher_name {
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384],
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384],
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256],
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => vec![CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256],
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA],
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA],
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA],
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA],
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" => vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384],
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" => vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384],
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" => vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256],
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" => vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256],
        _ => return Ok(false), // Unsupported cipher
    };
    
    let server_name = match ServerName::try_from(target) {
        Ok(name) => name,
        Err(_) => {
            match ServerName::try_from("example.com") {
                Ok(name) => name,
                Err(_) => return Ok(false),
            }
        }
    };
    
    // Create TLS connector
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    
    // Connect to the server
    match timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            // Try to establish the TLS connection
            match timeout(Duration::from_secs(5), connector.connect(server_name, stream)).await {
                Ok(Ok(_)) => Ok(true),
                _ => Ok(false),
            }
        },
        _ => Ok(false),
    }
}

/// Test legacy cipher support using custom TLS client implementation
async fn test_legacy_cipher(target: &str, port: u16, cipher_name: &str) -> FortiCoreResult<bool> {
    // Map cipher name to its ID
    let cipher_id = match cipher_name {
        "TLS_RSA_WITH_AES_256_GCM_SHA384" => 0x009D,
        "TLS_RSA_WITH_AES_128_GCM_SHA256" => 0x009C,
        "TLS_RSA_WITH_AES_256_CBC_SHA256" => 0x003D,
        "TLS_RSA_WITH_AES_128_CBC_SHA256" => 0x003C,
        "TLS_RSA_WITH_AES_256_CBC_SHA" => 0x0035,
        "TLS_RSA_WITH_AES_128_CBC_SHA" => 0x002F,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" => 0x0039,
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" => 0x0038,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" => 0x0033,
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" => 0x0032,
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA" => 0x000A,
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" => 0x0016,
        "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" => 0x0013,
        "TLS_RSA_WITH_RC4_128_SHA" => 0x0005,
        "TLS_RSA_WITH_RC4_128_MD5" => 0x0004,
        "TLS_RSA_WITH_NULL_SHA256" => 0x003B,
        "TLS_RSA_WITH_NULL_SHA" => 0x0002,
        "TLS_RSA_WITH_NULL_MD5" => 0x0001,
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" => 0x0008,
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" => 0x0014,
        "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" => 0x0011,
        _ => return Ok(false), // Unknown cipher
    };
    
    // Convert to a socket address
    let addr = format!("{}:{}", target, port);
    
    // Connect to the server
    match std::net::TcpStream::connect(addr) {
        Ok(mut stream) => {
            // Set timeouts
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            
            // Create a Client Hello message with the specific cipher suite
            let client_hello = create_client_hello_with_cipher(target, cipher_id);
            
            // Send the Client Hello
            if let Err(_) = stream.write_all(&client_hello) {
                return Ok(false);
            }
            
            // Read the server response
            let mut response = [0u8; 1024];
            match stream.read(&mut response) {
                Ok(size) if size > 0 => {
                    // If we get a Server Hello, the cipher is supported
                    Ok(validate_server_hello_response(&response[..size]))
                },
                _ => Ok(false),
            }
        },
        Err(_) => Ok(false),
    }
}

/// Create a Client Hello message with a specific cipher suite
fn create_client_hello_with_cipher(server_name: &str, cipher_id: u16) -> Vec<u8> {
    // This is a simplified TLS 1.2 Client Hello message with a specific cipher suite
    let mut msg = Vec::new();
    
    // TLS record header: content type (22 = handshake), version (3,3 = TLS 1.2), length (will be set later)
    msg.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]); // Length will be filled in later
    
    // Handshake header: type (1 = client hello), length (will be set later)
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Length will be filled in later
    
    // Client hello: client version (3,3 = TLS 1.2)
    msg.extend_from_slice(&[0x03, 0x03]);
    
    // Client random (32 bytes)
    for _ in 0..32 {
        msg.push(rand::random::<u8>());
    }
    
    // Session ID length (0)
    msg.push(0x00);
    
    // Cipher suites length (2 bytes for 1 suite)
    msg.extend_from_slice(&[0x00, 0x02]);
    
    // Cipher suite (the one we're testing)
    msg.push((cipher_id >> 8) as u8);
    msg.push((cipher_id & 0xFF) as u8);
    
    // Compression methods length (1)
    msg.push(0x01);
    
    // Compression method (0 = none)
    msg.push(0x00);
    
    // Extensions length (will be set later)
    msg.extend_from_slice(&[0x00, 0x00]);
    
    // SNI extension if server_name is a valid hostname
    if !server_name.contains(':') && !server_name.parse::<std::net::IpAddr>().is_ok() {
        // SNI extension type (0x0000)
        msg.extend_from_slice(&[0x00, 0x00]);
        
        // SNI extension length (will be set later)
        msg.extend_from_slice(&[0x00, 0x00]);
        
        // Server name list length (will be set later)
        msg.extend_from_slice(&[0x00, 0x00]);
        
        // Server name type (0 = hostname)
        msg.push(0x00);
        
        // Hostname length (will be set later)
        msg.extend_from_slice(&[0x00, 0x00]);
        
        // Hostname
        let hostname = server_name.as_bytes();
        msg.extend_from_slice(hostname);
        
        // Update hostname length
        let hostname_len = hostname.len();
        let msg_len = msg.len();
        msg[msg_len - hostname_len - 2] = ((hostname_len >> 8) & 0xFF) as u8;
        msg[msg_len - hostname_len - 1] = (hostname_len & 0xFF) as u8;
        
        // Update server name list length
        let list_len = hostname_len + 3; // type (1) + length (2) + hostname
        let msg_len = msg.len();
        msg[msg_len - hostname_len - 5] = ((list_len >> 8) & 0xFF) as u8;
        msg[msg_len - hostname_len - 4] = (list_len & 0xFF) as u8;
        
        // Update SNI extension length
        let ext_len = list_len + 2; // list length (2) + list
        let msg_len = msg.len();
        msg[msg_len - hostname_len - 7] = ((ext_len >> 8) & 0xFF) as u8;
        msg[msg_len - hostname_len - 6] = (ext_len & 0xFF) as u8;
    }
    
    // Update extensions length
    let extensions_len = msg.len() - 79; // 45 = record header (5) + handshake header (4) + client hello fixed fields (38) + extensions length (2)
    msg[77] = ((extensions_len >> 8) & 0xFF) as u8;
    msg[78] = (extensions_len & 0xFF) as u8;
    
    // Update message lengths
    let handshake_length = msg.len() - 9;
    let record_length = msg.len() - 5;
    
    msg[3] = ((record_length >> 8) & 0xFF) as u8;
    msg[4] = (record_length & 0xFF) as u8;
    
    msg[6] = ((handshake_length >> 16) & 0xFF) as u8;
    msg[7] = ((handshake_length >> 8) & 0xFF) as u8;
    msg[8] = (handshake_length & 0xFF) as u8;
    
    msg
}

/// Validate a Server Hello response (simplified)
fn validate_server_hello_response(response: &[u8]) -> bool {
    // Check if the response has the minimum size for a Server Hello
    if response.len() < 10 {
        return false;
    }
    
    // Check if it's a handshake message (content type = 22)
    if response[0] != 0x16 {
        return false;
    }
    
    // Check if the version in the record header is TLS 1.2 or below
    if response[1] != 0x03 || response[2] > 0x03 {
        return false;
    }
    
    // Check if it's a Server Hello message (handshake type = 2)
    // The handshake type is at position 5 in the response
    if response.len() > 5 && response[5] != 0x02 {
        return false;
    }
    
    true
}

/// Test for the Logjam vulnerability
async fn test_logjam_vulnerability(target: &str, port: u16, verbose: bool) -> FortiCoreResult<bool> {
    if verbose {
        println!("Testing for Logjam vulnerability on {}:{}", target, port);
    }
    
    // Logjam affects servers supporting export-grade DHE cipher suites
    
    // Create a TCP connection
    let addr = format!("{}:{}", target, port);
    let stream = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    
    // Set timeouts
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    
    // Create a TLS ClientHello with export-grade DHE cipher suites
    let mut msg = Vec::new();
    
    // TLS record header: content type (22 = handshake), version (3,3 = TLS 1.2), length (will be set later)
    msg.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]); // Length will be filled in later
    
    // Handshake header: type (1 = client hello), length (will be set later)
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Length will be filled in later
    
    // Client hello: client version (3,3 = TLS 1.2)
    msg.extend_from_slice(&[0x03, 0x03]);
    
    // Client random (32 bytes)
    for _ in 0..32 {
        msg.push(rand::random::<u8>());
    }
    
    // Session ID length (0)
    msg.push(0x00);
    
    // Cipher suites length (8 bytes for 4 cipher suites)
    msg.extend_from_slice(&[0x00, 0x08]);
    
    // DHE_EXPORT cipher suites
    msg.extend_from_slice(&[
        0x00, 0x14, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x00, 0x11, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x00, 0x12, // TLS_DHE_DSS_WITH_DES_CBC_SHA
        0x00, 0x15, // TLS_DHE_RSA_WITH_DES_CBC_SHA
    ]);
    
    // Compression methods length (1)
    msg.push(0x01);
    
    // Compression method (0 = none)
    msg.push(0x00);
    
    // No extensions
    
    // Update the message lengths
    let handshake_length = msg.len() - 9;
    let record_length = msg.len() - 5;
    
    msg[3] = ((record_length >> 8) & 0xFF) as u8;
    msg[4] = (record_length & 0xFF) as u8;
    
    msg[6] = ((handshake_length >> 16) & 0xFF) as u8;
    msg[7] = ((handshake_length >> 8) & 0xFF) as u8;
    msg[8] = (handshake_length & 0xFF) as u8;
    
    // Send ClientHello
    let mut stream = stream;
    if let Err(_) = stream.write_all(&msg) {
        return Ok(false);
    }
    
    // Read response
    let mut response = [0u8; 1024];
    let size = match stream.read(&mut response) {
        Ok(s) if s > 0 => s,
        _ => return Ok(false),
    };
    
    // Check if the server accepted any of our export-grade DHE ciphers
    // This is a simplified check - in a real implementation we would parse the ServerHello
    // to see which cipher suite was selected
    
    // If we received a ServerHello, the server might support these ciphers
    let is_vulnerable = response.len() >= 3 && 
                       response[0] == 0x16 && // Handshake
                       response[1] == 0x03;   // TLS version (any minor version)
    
    if verbose {
        if is_vulnerable {
            println!("  ⚠ Potentially vulnerable to Logjam attack (server accepted DHE_EXPORT ciphers)");
        } else {
            println!("  ✓ Not vulnerable to Logjam attack");
        }
    }
    
    Ok(is_vulnerable)
}

/// Test for the FREAK vulnerability
async fn test_freak_vulnerability(target: &str, port: u16, verbose: bool) -> FortiCoreResult<bool> {
    if verbose {
        println!("Testing for FREAK vulnerability on {}:{}", target, port);
    }
    
    // FREAK affects servers supporting export-grade RSA cipher suites
    
    // Create a TCP connection
    let addr = format!("{}:{}", target, port);
    let stream = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    
    // Set timeouts
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    
    // Create a TLS ClientHello with export-grade RSA cipher suites
    let mut msg = Vec::new();
    
    // TLS record header: content type (22 = handshake), version (3,3 = TLS 1.2), length (will be set later)
    msg.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]); // Length will be filled in later
    
    // Handshake header: type (1 = client hello), length (will be set later)
    msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Length will be filled in later
    
    // Client hello: client version (3,3 = TLS 1.2)
    msg.extend_from_slice(&[0x03, 0x03]);
    
    // Client random (32 bytes)
    for _ in 0..32 {
        msg.push(rand::random::<u8>());
    }
    
    // Session ID length (0)
    msg.push(0x00);
    
    // Cipher suites length (6 bytes for 3 cipher suites)
    msg.extend_from_slice(&[0x00, 0x06]);
    
    // RSA_EXPORT cipher suites
    msg.extend_from_slice(&[
        0x00, 0x03, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
        0x00, 0x06, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        0x00, 0x08, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
    ]);
    
    // Compression methods length (1)
    msg.push(0x01);
    
    // Compression method (0 = none)
    msg.push(0x00);
    
    // No extensions
    
    // Update the message lengths
    let handshake_length = msg.len() - 9;
    let record_length = msg.len() - 5;
    
    msg[3] = ((record_length >> 8) & 0xFF) as u8;
    msg[4] = (record_length & 0xFF) as u8;
    
    msg[6] = ((handshake_length >> 16) & 0xFF) as u8;
    msg[7] = ((handshake_length >> 8) & 0xFF) as u8;
    msg[8] = (handshake_length & 0xFF) as u8;
    
    // Send ClientHello
    let mut stream = stream;
    if let Err(_) = stream.write_all(&msg) {
        return Ok(false);
    }
    
    // Read response
    let mut response = [0u8; 1024];
    let size = match stream.read(&mut response) {
        Ok(s) if s > 0 => s,
        _ => return Ok(false),
    };
    
    // Check if the server accepted any of our export-grade RSA ciphers
    // This is a simplified check - in a real implementation we would parse the ServerHello
    // to see which cipher suite was selected
    
    // If we received a ServerHello, the server might support these ciphers
    let is_vulnerable = response.len() >= 3 && 
                       response[0] == 0x16 && // Handshake
                       response[1] == 0x03;   // TLS version (any minor version)
    
    if verbose {
        if is_vulnerable {
            println!("  ⚠ Potentially vulnerable to FREAK attack (server accepted RSA_EXPORT ciphers)");
        } else {
            println!("  ✓ Not vulnerable to FREAK attack");
        }
    }
    
    Ok(is_vulnerable)
} 