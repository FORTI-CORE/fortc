use crate::utils::error::FortiCoreResult;
use reqwest::Client;
use std::collections::HashSet;
use std::fs;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

/// Enumerates subdomains of the given domain using various techniques
pub async fn enumerate_subdomains(
    client: &Client,
    domain: &str,
    verbose: bool,
) -> FortiCoreResult<HashSet<String>> {
    let mut subdomains = HashSet::new();

    // Attempt passive subdomain enumeration first
    if verbose {
        println!("Attempting passive subdomain enumeration for: {}", domain);
    }

    // Try to find common subdomains
    check_common_subdomains(client, domain, &mut subdomains, verbose).await;

    // Try DNS zone transfers and other DNS-based methods
    if let Ok(dns_subdomains) = enumerate_dns_subdomains(domain, verbose).await {
        for subdomain in dns_subdomains {
            subdomains.insert(subdomain);
        }
    }

    if verbose {
        println!("Found {} subdomains for {}", subdomains.len(), domain);
        for subdomain in &subdomains {
            println!("  - {}", subdomain);
        }
    }

    Ok(subdomains)
}

/// Check for common subdomains based on a wordlist
async fn check_common_subdomains(
    client: &Client,
    domain: &str,
    subdomains: &mut HashSet<String>,
    verbose: bool,
) {
    let common_subdomains = [
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "webdisk",
        "ns2",
        "cpanel",
        "whm",
        "autodiscover",
        "autoconfig",
        "m",
        "imap",
        "test",
        "ns",
        "blog",
        "pop3",
        "dev",
        "www2",
        "admin",
        "forum",
        "news",
        "vpn",
        "ns3",
        "mail2",
        "new",
        "mysql",
        "old",
        "lists",
        "support",
        "mobile",
        "mx",
        "static",
        "docs",
        "beta",
        "shop",
        "sql",
        "secure",
        "demo",
        "cp",
        "calendar",
        "wiki",
        "web",
        "media",
        "email",
        "images",
        "img",
        "www1",
        "intranet",
        "portal",
        "video",
        "sip",
        "dns2",
        "api",
        "cdn",
        "stats",
        "dns1",
        "ns4",
        "www3",
        "dns",
        "search",
        "staging",
        "server",
        "mx1",
        "chat",
        "wap",
        "my",
        "svn",
        "mail1",
        "sites",
        "proxy",
        "ads",
        "host",
        "crm",
        "cms",
        "backup",
        "mx2",
        "lyncdiscover",
        "info",
        "apps",
        "download",
        "remote",
        "db",
        "forums",
        "store",
        "relay",
        "files",
        "newsletter",
        "app",
        "live",
        "owa",
        "en",
        "start",
        "sms",
        "office",
        "exchange",
        "ipv4",
        "staging2",
        "monitor",
        "login",
        "service",
        "core",
        "hq",
        "auth",
        "catalog",
        "account",
        "event",
        "cloud",
        "dashboard",
        "internal",
        "gateway",
        "mail3",
        "corporate",
        "developer",
        "private",
        "control",
        "analytics",
        "tickets",
        "help",
        "platform",
        "tracking",
        "portal2",
    ];

    let resolver = match Resolver::from_system_conf() {
        Ok(r) => r,
        Err(_) => {
            if verbose {
                println!("Failed to create system DNS resolver, falling back to Google DNS");
            }
            match Resolver::new(ResolverConfig::google(), ResolverOpts::default()) {
                Ok(r) => r,
                Err(_) => {
                    if verbose {
                        println!("Failed to create Google DNS resolver, skipping DNS checks");
                    }
                    return;
                }
            }
        }
    };

    let mut count = 0;
    for &subdomain_prefix in &common_subdomains {
        let full_domain = format!("{}.{}", subdomain_prefix, domain);

        // Check if subdomain resolves via DNS
        match resolver.lookup_ip(&full_domain) {
            Ok(lookup) => {
                if !lookup.iter().next().is_none() {
                    subdomains.insert(full_domain.clone());
                    count += 1;

                    if verbose && count % 10 == 0 {
                        println!("Found {} subdomains so far...", count);
                    }
                }
            }
            Err(_) => {} // Ignore DNS lookup failures
        }

        // Throttle requests to avoid being blocked
        sleep(Duration::from_millis(100)).await;
    }
}

/// Attempts to perform DNS-based subdomain enumeration, including zone transfers if allowed
async fn enumerate_dns_subdomains(domain: &str, verbose: bool) -> FortiCoreResult<HashSet<String>> {
    let mut subdomains = HashSet::new();

    // Try to get NS records for the domain
    let resolver = Resolver::from_system_conf()?;

    if verbose {
        println!("Attempting DNS-based enumeration for: {}", domain);
    }

    // This is a simplified version - a real implementation would attempt zone transfers
    // from each nameserver and use more advanced techniques

    Ok(subdomains)
}

/// Checks a subdomain endpoint for responsiveness
pub async fn check_api_endpoint(client: &Client, target: &str, verbose: bool) -> bool {
    match client.get(target).send().await {
        Ok(response) => {
            let status = response.status();
            if verbose {
                println!("Response from {}: {}", target, status);
            }
            status.is_success() || status.as_u16() == 401 || status.as_u16() == 403
        }
        Err(_) => false,
    }
}
