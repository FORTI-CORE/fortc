# FortiCore

FortiCore is an automated Penetration Testing Tool (PTT) designed to simplify penetration testing processes.

## Features

- User-friendly CLI interface for automated vulnerability scanning
- Network vulnerability scanning (port scanning, service detection, etc.)
- Web application scanning (XSS, SQL injection, etc.)
- Safe exploitation of discovered vulnerabilities
- Detailed report generation in PDF and TXT formats

## Installation

### Prerequisites

- Rust and Cargo (1.70.0 or newer)
- OpenSSL development libraries
- Linux-based system (Ubuntu/Debian/CentOS/RHEL)

### Automatic Installation

```bash
sudo ./install.sh
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

# Full scan (all scan types)
fortc scan -t example.com -s full -o scan-results.json
```

### Exploit Mode

```bash
# Attempt to exploit a specific vulnerability
fortc exploit -t example.com --vuln-id WEB-004

# Run discovery and exploitation in safe mode (default)
fortc exploit -t 192.168.1.1 --safe-mode true
```

### Report Generation

```bash
# Generate a PDF report from scan results
fortc report -i scan-results.json -o security-report.pdf

# Generate a text report
fortc report -i scan-results.json -o security-report.txt
```

### Interactive Mode

```bash
# Start the interactive mode
fortc interactive
```

## Modules

- **Scanner Modules**: Detect vulnerabilities in networks and web applications
- **Exploit Modules**: Safely exploit discovered vulnerabilities to demonstrate risk
- **Report Modules**: Generate comprehensive reports with findings and remediation steps

## Security Notice

FortiCore is designed for legitimate security testing with proper authorization. Unauthorized testing of systems you don't own or have permission to test is illegal and unethical.

## License

MIT License

## Disclaimer

This tool is provided for educational and professional use only. The authors are not responsible for any misuse or damage caused by this tool.
