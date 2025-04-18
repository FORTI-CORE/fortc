# FortiCore

FortiCore is an automated Penetration Testing Tool (PTT) designed to simplify penetration testing processes.

## Features

- User-friendly CLI interface for automated vulnerability scanning
- Network vulnerability scanning (port scanning, service detection, etc.)
- Web application scanning (XSS, SQL injection, etc.)
- API endpoint discovery (both subdomain prefixes and path suffixes)
- Enhanced DNS enumeration including zone transfer analysis
- Dedicated vulnerability scanner for IP-based targets
- JWT token security analysis
- SSL/TLS configuration analysis for detecting weak ciphers and vulnerabilities
- Safe exploitation of discovered vulnerabilities
- Detailed report generation in PDF and TXT formats
- Automatic scan results storage in local 'scans' directory

## Installation

### Prerequisites

- Rust and Cargo (1.70.0 or newer)
- OpenSSL development libraries
- Linux-based system (Ubuntu/Debian/CentOS/RHEL)

### Automatic Installation

Run as root in the fortc directory

```bash
source "/root/.cargo/env" && bash install.sh
```

### Manual Installation

1. Install dependencies:

   For Debian/Ubuntu:

   ```bash
   sudo apt-get update
   sudo apt-get install -y build-essential pkg-config libssl-dev
   ```

   For CentOS/RHEL/Fedora:

   ```bash
   sudo yum groupinstall -y "Development Tools"
   sudo yum install -y openssl-devel
   ```

2. Build and install:
   ```bash
   cargo build --release
   sudo cp target/release/fortc /usr/local/bin/
   sudo chmod +x /usr/local/bin/fortc
   ```

## Usage

FortiCore can be used in several modes:

### Scan Mode

```bash
# Basic scan on a target
fortc scan -t example.com

# Network scan with output file
fortc scan -t 192.168.1.1 -s network -o scan-results.json

# Web application scan in verbose mode
fortc scan -t https://example.com -s web -v

# Web application scan with subdomain discovery
fortc scan -t example.com -s web --scan-subdomains

# Vulnerability scan for IP-based targets
fortc scan -t 192.168.1.100 -s vuln -v

# SSL/TLS configuration analysis
fortc scan -t example.com -s ssl -v

# Full scan (Comprehensive port scan)
fortc scan -t example.com -s full -o scan-results.json
```

### Exploit Mode (In development)

```bash
# Attempt to exploit a specific vulnerability
fortc exploit -t example.com --vuln-id WEB-004

# Run discovery and exploitation in safe mode (default)
fortc exploit -t 192.168.1.1 --safe-mode true

# Specify a custom scan results file
fortc exploit -t example.com --scan-file path/to/custom-scan-results.json

# Save exploitation results to a file
fortc exploit -t example.com -o exploit-results.json

# Generate a PDF report of exploitation results
fortc exploit -t example.com -o exploit-results.json --generate-report
```

### Report Generation

```bash
# Generate a PDF report from scan results
fortc report -i scan-results.json -o security-report.pdf

# Generate a text report
fortc report -i scan-results.json -o security-report.txt

# Generate a report from exploitation results
fortc report -i exploit-results.json -o exploit-report.pdf
```

### Interactive Mode (Coming Soon)

```bash
# Start the interactive mode
fortc interactive
# Or simply
fortc
```

## Modules

- **Scanner Modules**:
  - **Web Scanner**: Detects vulnerabilities in web applications, including XSS, SQL injection, insecure JWT implementations, and more
  - **Network Scanner**: Identifies open ports and vulnerable network services
  - **Vulnerability Scanner**: Focused on detecting vulnerabilities in IP-based targets
  - **SSL Scanner**: Analyzes SSL/TLS configurations to identify weak ciphers, protocols, and vulnerabilities (BEAST, POODLE, Heartbleed, etc.)
  - **Port Scanner**: Advanced port scanning with service detection
- **Exploit Modules**: Safely exploit discovered vulnerabilities to demonstrate risk
  - **Web Exploit**: Exploits web vulnerabilities like XSS and SQL Injection
  - **Network Exploit**: Exploits network-level vulnerabilities
  - **SSL Exploit**: Exploits SSL/TLS vulnerabilities including weak ciphers, protocol downgrades, and certificate issues
- **Report Modules**: Generate comprehensive reports with findings and remediation steps

## Scan to Exploit Workflow

FortiCore implements an automated workflow from scanning to exploitation:

1. Run a scan to identify vulnerabilities:

   ```
   fortc scan -t example.com -s full -o scan-results.json
   ```

2. Exploit discovered vulnerabilities:

   ```
   fortc exploit -t example.com
   ```

   This will:

   - Automatically locate the most recent scan results for the target
   - Filter vulnerabilities that are marked as exploitable
   - Prioritize vulnerabilities by severity
   - Attempt exploitation in order of priority
   - Report successful exploits

3. If you've saved scan results to a custom location, specify the file:

   ```
   fortc exploit -t example.com --scan-file path/to/scan-results.json
   ```

4. Alternatively, exploit a specific vulnerability:

   ```
   fortc exploit -t example.com --vuln-id WEB-001
   ```

5. Control safety with safe mode:

   ```
   fortc exploit -t example.com --safe-mode true
   ```

   When safe mode is enabled (default), FortiCore will only perform non-destructive exploitation.

## Supported Exploit Types

FortiCore supports exploitation of the following vulnerability types:

### Web Vulnerabilities

- **WEB-001/WEB-004**: Cross-Site Scripting (XSS)
- **WEB-002/WEB-005**: SQL Injection
- **WEB-003**: CORS Misconfiguration
- **WEB-CMS-001**: Content Management System (CMS) Vulnerabilities
  - WordPress
  - Drupal
  - Joomla
  - Magento
  - Generic CMS vulnerabilities

### Network Vulnerabilities

- **NET-001**: Telnet Service Enabled
- **NET-002**: FTP Service Enabled
- **NET-006**: Remote Desktop Service Exposed
- **NET-007**: NetBIOS/SMB Services Exposed
- **NET-010**: Microsoft SQL Server Exposed
- **NET-011**: MySQL Database Exposed
- **NET-012**: PostgreSQL Database Exposed
- **NET-013**: Redis Server Exposed
- **NET-014**: MongoDB Server Exposed

### SSL/TLS Vulnerabilities

- **SSL-001**: Weak cipher suites
- **SSL-002**: TLS protocol downgrade vulnerabilities
- **SSL-003**: Certificate validation issues
- **SSL-004**: Heartbleed vulnerability

### Additional Vulnerability IDs

- **VULN-FTP-ANON**: Anonymous FTP Access
- **VULN-SMB-SAMBA**: Potentially Vulnerable SMB Service
- **VULN-MYSQL-EXPOSURE**: MySQL Database Exposed
- **VULN-POSTGRES-EXPOSURE**: PostgreSQL Database Exposed
- **VULN-BACKDOOR-1524**: Potential Shell Backdoor

## Scan Results Storage

By default, all scan results are automatically saved in the `./scans` directory in the current working directory. The filename format is:

```
<target>_<scan_type>_<timestamp>.json
```

If the local directory isn't writable, FortiCore will fall back to saving in:

1. User's home directory at `~/.forticore/scans/`
2. System directory at `/var/lib/forticore/scans/`

## Security Notice

FortiCore is designed for legitimate security testing with proper authorization. Unauthorized testing of systems you don't own or have permission to test is illegal and unethical.

## Disclaimer

This tool is provided for educational and professional use only. The authors are not responsible for any misuse or damage caused by this tool.
