# FortiCore Web Scanner

The web scanner module performs comprehensive security scans against web applications and services. It includes several components that work together:

## Components

- **subdomain.rs**: Enumerates subdomains of a target domain
- **common.rs**: Checks for common web vulnerabilities (XSS, SQL injection, etc.)
- **cms.rs**: Detects content management systems and their vulnerabilities
- **auth.rs**: Analyzes authentication mechanisms for security issues
- **utils.rs**: Utility functions for HTTP operations and URL handling

## Subdomain Scanner

The subdomain scanner uses multiple techniques to discover subdomains:

### DNS-based Enumeration

- **Multiple DNS Resolvers**: Uses Google, Cloudflare, Quad9, and system DNS servers for fallback robustness
- **Record Types**: Checks A, AAAA, and CNAME records for each potential subdomain
- **MX Record Analysis**: Extracts mail server subdomains from MX records
- **Timeout Handling**: Implements proper error handling for slow or failed DNS queries

### HTTP-based Enumeration

- Performs HTTP and HTTPS connectivity tests on potential subdomains
- Detects subdomains that might be behind CDNs or non-standard DNS configurations

### Troubleshooting Subdomain Scanning

If subdomain scanning is not finding results:

1. **Possible Causes**:

   - DNS rate limiting by the target domain
   - Network/DNS connectivity issues
   - Target domain may have few or no subdomains
   - The domain's DNS servers may be blocking bulk queries

2. **Solutions**:

   - Run with `--verbose` flag to see detailed progress and diagnostics
   - Try scanning with fewer subdomains
   - Check your network connectivity and DNS configuration
   - Consider adding custom subdomains to `resources/subdomains.json`

3. **Customization**:
   - Add custom subdomains to `resources/subdomains.json` using the resources update script
   - Run `python scripts/update_resources.py add subdomains.json common_subdomains new-subdomain.example.com`

## Usage

```bash
# Basic web scan without subdomain enumeration
fortc scan -t example.com -s web

# Web scan with subdomain enumeration (slower but more thorough)
fortc scan -t example.com -s web --scan-subdomains

# Verbose output for debugging
fortc scan -t example.com -s web --scan-subdomains -v
```

## Performance Considerations

- Subdomain scanning can be time-consuming with large wordlists
- The scanner uses various techniques to optimize speed:
  - Parallel DNS queries
  - Timeouts to prevent hanging on slow responses
  - Selective HTTP checks (not for every potential subdomain)
  - Early termination for valid findings
