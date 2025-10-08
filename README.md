# FortiCore

[![Release](https://img.shields.io/github/v/release/FORTI-CORE/fortc?style=flat-square)](https://github.com/FORTI-CORE/fortc/releases)
[![Downloads](https://img.shields.io/github/downloads/FORTI-CORE/fortc/total?style=flat-square)](https://github.com/FORTI-CORE/fortc/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)

FortiCore is an automated Penetration Testing Tool (PTT) designed to simplify penetration testing processes.

**[📥 Download Latest Release](https://github.com/FORTI-CORE/fortc/releases/latest)**

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

### Option 1: Docker (Recommended)

The easiest way to run FortiCore is using Docker:

```bash
# Build the Docker image
docker build -t forticore:latest .

# Or use the helper script
chmod +x docker-run.sh
./docker-run.sh build

# Run a scan
./docker-run.sh scan -t example.com -s web -v

# Or use docker-compose
docker-compose run forticore scan -t example.com -s web
```

See the [Docker Usage](#docker-usage) section below for more details.

### Option 2: Debian Package (Pre-built)

Download and install the latest release:

```bash
# Download the latest release
wget https://github.com/FORTI-CORE/fortc/releases/latest/download/forticore_0.1.0-1_amd64.deb

# Install the package
sudo dpkg -i forticore_0.1.0-1_amd64.deb

# If there are missing dependencies, run:
sudo apt-get install -f
```

Or download directly from the [Releases page](https://github.com/FORTI-CORE/fortc/releases).

#### Build Your Own Debian Package

```bash
# Install cargo-deb if not already installed
cargo install cargo-deb

# Build the package
cargo deb

# Install the package
sudo dpkg -i target/debian/forticore_*.deb
```

### Option 3: From Source

#### Prerequisites

- Rust and Cargo (1.70.0 or newer)
- OpenSSL development libraries
- Linux-based system (Ubuntu/Debian/CentOS/RHEL)

#### Automatic Installation

Run as root in the fortc directory:

```bash
source "/root/.cargo/env" && bash install.sh
```

#### Manual Installation

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

## Docker Usage

FortiCore is fully containerized for easy deployment and isolation.

### Building the Docker Image

```bash
# Build using Docker directly
docker build -t forticore:latest .

# Or use the helper script
chmod +x docker-run.sh
./docker-run.sh build
```

### Running Scans with Docker

#### Using the Helper Script (Recommended)

```bash
# Web application scan
./docker-run.sh scan -t example.com -s web -v

# Network scan
./docker-run.sh scan -t 192.168.1.0/24 -s network

# Full scan with subdomain discovery
./docker-run.sh scan -t example.com -s full --scan-subdomains

# SSL/TLS analysis
./docker-run.sh scan -t example.com -s ssl -v
```

#### Using Docker Directly

```bash
# Create scans directory
mkdir -p ./scans

# Run a scan
docker run --rm \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v "$(pwd)/scans:/home/fortc/scans" \
  forticore:latest scan -t example.com -s web -v
```

#### Using Docker Compose

```bash
# Run with docker-compose
docker-compose run forticore scan -t example.com -s web

# Run in isolated network mode
docker-compose --profile isolated run forticore-isolated scan -t example.com -s web
```

### Running Exploits with Docker

```bash
# Using helper script
./docker-run.sh exploit -t example.com --safe-mode true

# Using Docker directly
docker run --rm \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v "$(pwd)/scans:/home/fortc/scans" \
  forticore:latest exploit -t example.com --safe-mode true
```

### Generating Reports with Docker

```bash
# Using helper script
./docker-run.sh report scans/example_com_Web_20251008.json reports/report.pdf

# Using Docker directly
docker run --rm \
  -v "$(pwd)/scans:/home/fortc/scans" \
  -v "$(pwd)/reports:/home/fortc/reports" \
  forticore:latest report -i scans/scan.json -o reports/report.pdf
```

### Interactive Shell

```bash
# Start an interactive shell in the container
./docker-run.sh shell

# Or with Docker directly
docker run --rm -it \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v "$(pwd)/scans:/home/fortc/scans" \
  --entrypoint /bin/bash \
  forticore:latest
```

### Docker Security Considerations

FortiCore requires elevated network capabilities for scanning operations:

- **NET_RAW**: Required for raw socket operations (port scanning, packet crafting)
- **NET_ADMIN**: Required for network interface manipulation
- **--network host**: Provides direct access to the host's network stack

**Important**: Only use these capabilities in authorized testing environments. The container runs as a non-root user (`fortc`) for additional security.

### Persistent Storage

Scan results are stored in mounted volumes:

```bash
# Results are saved to ./scans on the host
ls -la ./scans/

# Reports are saved to ./reports on the host
ls -la ./reports/
```

## Security Notice

FortiCore is designed for legitimate security testing with proper authorization. Unauthorized testing of systems you don't own or have permission to test is illegal and unethical.

## Disclaimer

This tool is provided for educational and professional use only. The authors are not responsible for any misuse or damage caused by this tool.
