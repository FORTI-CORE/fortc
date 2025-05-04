use crate::resources;
use crate::utils::error::{FortiCoreError, FortiCoreResult};
use reqwest::Client;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

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
    check_common_subdomains(client, domain, &mut subdomains, verbose).await?;

    // Try DNS zone transfers and other DNS-based methods
    if let Ok(dns_subdomains) = enumerate_dns_subdomains(domain, verbose).await {
        for subdomain in dns_subdomains {
            subdomains.insert(subdomain);
        }
    }

    if verbose {
        println!("Found {} subdomains for {}", subdomains.len(), domain);

        if subdomains.is_empty() {
            println!("No subdomains found. This could be due to:");
            println!("  - Domain may have strong DNS security measures");
            println!("  - The domain may not have many public subdomains");
            println!("  - There might be network connectivity issues");
            println!("  - DNS servers might be blocking enumeration requests");
            println!("Try adding more subdomain patterns to resources/subdomains.json");
        } else {
            for subdomain in &subdomains {
                println!("  - {}", subdomain);
            }
        }
    }

    Ok(subdomains)
}

/// Create a DNS resolver for subdomain enumeration
/// Try multiple DNS resolvers in case some are blocked
async fn create_resolver(verbose: bool) -> FortiCoreResult<TokioAsyncResolver> {
    // Standard resolver options
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.timeout = Duration::from_secs(2); // Shorter timeout for faster scanning
    resolver_opts.attempts = 1; // Only try once per subdomain

    // Try different resolver configurations in order
    let resolver_configs = [
        ("Google", ResolverConfig::google()),
        ("Cloudflare", ResolverConfig::cloudflare()),
        ("Quad9", ResolverConfig::quad9()),
        ("System Default", ResolverConfig::default()),
    ];

    for (name, config) in resolver_configs {
        if verbose {
            println!("Attempting to create DNS resolver using {} servers", name);
        }

        match std::panic::catch_unwind(|| {
            TokioAsyncResolver::tokio(config.clone(), resolver_opts.clone())
        }) {
            Ok(resolver) => {
                if verbose {
                    println!("Successfully created DNS resolver using {} servers", name);
                }
                return Ok(resolver);
            }
            Err(_) => {
                if verbose {
                    println!("Failed to create DNS resolver with {} servers", name);
                }
                continue;
            }
        }
    }

    // If all resolvers fail, return an error
    Err(FortiCoreError::NetworkError(
        "Failed to create any DNS resolver. Check your network connection and DNS settings."
            .to_string(),
    ))
}

/// Check for common subdomains based on a wordlist
async fn check_common_subdomains(
    client: &Client,
    domain: &str,
    subdomains: &mut HashSet<String>,
    verbose: bool,
) -> FortiCoreResult<()> {
    // Load common subdomains from resources
    let common_subdomains = resources::load_subdomains()?;

    if verbose {
        println!(
            "Loaded {} common subdomains from resources",
            common_subdomains.len()
        );
        println!("Beginning DNS lookups for common subdomains");
        println!("Will try multiple DNS providers (Google, Cloudflare, Quad9, System)");
    }

    // Create the resolver using our new function
    let resolver = create_resolver(verbose).await?;

    if verbose {
        println!("DNS resolver created successfully");
        println!("Using record types: A, AAAA, and CNAME for subdomain detection");
        println!("Will perform HTTP connectivity checks for some subdomains");
        println!("Testing subdomains (this may take some time)...");
    }

    let mut count = 0;
    let mut active_checks = 0;
    let mut dns_lookup_count = 0;
    let mut dns_failures = 0;
    let mut http_checks = 0;
    let mut http_successes = 0;

    for (index, subdomain_prefix) in common_subdomains.iter().enumerate() {
        let full_domain = format!("{}.{}", subdomain_prefix, domain);

        if verbose && index % 50 == 0 && index > 0 {
            println!(
                "Progress: Checked {}/{} subdomains...",
                index,
                common_subdomains.len()
            );
        }

        // Try A records first (IPv4)
        dns_lookup_count += 1;
        let result = check_subdomain_exists(&resolver, &full_domain, RecordType::A).await;
        if result {
            subdomains.insert(full_domain.clone());
            count += 1;
            if verbose {
                println!("Found subdomain via A record: {}", full_domain);
            }
            continue; // Found it, no need to check other record types
        }

        // Try AAAA records (IPv6) if A record wasn't found
        dns_lookup_count += 1;
        let result = check_subdomain_exists(&resolver, &full_domain, RecordType::AAAA).await;
        if result {
            subdomains.insert(full_domain.clone());
            count += 1;
            if verbose {
                println!("Found subdomain via AAAA record: {}", full_domain);
            }
            continue;
        }

        // Try CNAME record
        dns_lookup_count += 1;
        let result = check_subdomain_exists(&resolver, &full_domain, RecordType::CNAME).await;
        if result {
            subdomains.insert(full_domain.clone());
            count += 1;
            if verbose {
                println!("Found subdomain via CNAME record: {}", full_domain);
            }
            continue;
        } else {
            dns_failures += 1;
        }

        // For every 10th subdomain, try an active HTTP check even if DNS record not found
        // This can find subdomains behind CDNs or with unusual DNS configurations
        active_checks += 1;
        if active_checks % 10 == 0 {
            let http_url = format!("http://{}", full_domain);
            let https_url = format!("https://{}", full_domain);

            http_checks += 1;
            // Try HTTPS first
            if check_url_connectivity(client, &https_url).await {
                subdomains.insert(full_domain.clone());
                count += 1;
                http_successes += 1;
                if verbose {
                    println!("Found subdomain via HTTPS connectivity: {}", full_domain);
                }
                continue;
            }

            // Try HTTP if HTTPS fails
            if check_url_connectivity(client, &http_url).await {
                subdomains.insert(full_domain.clone());
                count += 1;
                http_successes += 1;
                if verbose {
                    println!("Found subdomain via HTTP connectivity: {}", full_domain);
                }
                continue;
            }
        }

        // Brief delay to avoid rate limiting
        sleep(Duration::from_millis(50)).await;
    }

    if verbose {
        println!("Subdomain enumeration complete");
        println!("DNS lookups performed: {}", dns_lookup_count);
        println!("DNS lookups failed: {}", dns_failures);
        println!("HTTP connectivity checks: {}", http_checks);
        println!("HTTP checks successful: {}", http_successes);

        if count > 0 {
            println!(
                "Found {} subdomains through DNS lookups and connectivity checks",
                count
            );
        } else {
            println!("No subdomains found. This could be due to:");
            println!("  - DNS rate limiting or blocking (common with security-conscious domains)");
            println!("  - Network connectivity issues or DNS resolution problems");
            println!("  - The domain doesn't have common subdomains in our wordlist");
            println!("  - The domain's DNS servers may be blocking zone transfers or bulk queries");

            if dns_failures > 500 {
                println!("\nA high number of DNS query failures suggests possible rate limiting.");
                println!("Try running the scan with fewer subdomains or at a slower rate.");
            }
        }
    }

    Ok(())
}

/// Check if a URL is accessible
async fn check_url_connectivity(client: &Client, url: &str) -> bool {
    match timeout(Duration::from_secs(5), client.get(url).send()).await {
        Ok(Ok(response)) => {
            let status = response.status();
            // Consider all responses except server errors as valid
            status.is_success()
                || status.as_u16() == 401
                || status.as_u16() == 403
                || status.as_u16() == 404
                || status.as_u16() == 302
                || status.as_u16() == 301
        }
        _ => false,
    }
}

/// Check if a subdomain exists using the specified record type
async fn check_subdomain_exists(
    resolver: &TokioAsyncResolver,
    domain: &str,
    record_type: RecordType,
) -> bool {
    // Add a timeout for DNS lookup
    let dns_future = resolver.lookup(domain, record_type);
    match timeout(Duration::from_secs(3), dns_future).await {
        Ok(result) => match result {
            Ok(lookup) => !lookup.is_empty(),
            Err(e) => {
                // Check if error is rate limiting or NXDOMAIN (expected for non-existent domains)
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("nxdomain")
                    || err_str.contains("no such host")
                    || err_str.contains("not found")
                {
                    // This is normal for non-existent domains
                    false
                } else if err_str.contains("rate limit")
                    || err_str.contains("throttle")
                    || err_str.contains("timeout")
                {
                    // DNS rate limiting might be in effect
                    false
                } else {
                    // Other unexpected errors, but we'll continue
                    false
                }
            }
        },
        Err(_) => false, // Timeout occurred
    }
}

/// Attempts to perform DNS-based subdomain enumeration, including zone transfers if allowed
async fn enumerate_dns_subdomains(domain: &str, verbose: bool) -> FortiCoreResult<HashSet<String>> {
    let mut subdomains = HashSet::new();

    // Create resolver using our new function
    let resolver = create_resolver(verbose).await?;

    if verbose {
        println!("Attempting DNS-based enumeration for: {}", domain);
    }

    // Try to find nameservers for the domain
    match resolver.lookup(domain, RecordType::NS).await {
        Ok(ns_lookup) => {
            for record in ns_lookup.iter() {
                let ns_name = record.to_string();
                if verbose {
                    println!("Found nameserver: {}", ns_name);
                }

                // Try to find subdomains via MX records
                if let Ok(mx_lookup) = resolver.lookup(domain, RecordType::MX).await {
                    for mx_record in mx_lookup.iter() {
                        let mx_name = mx_record.to_string();
                        // Extract the hostname part
                        if let Some(hostname) = mx_name.split_whitespace().nth(1) {
                            if hostname.ends_with(domain) {
                                subdomains.insert(hostname.to_string());
                                if verbose {
                                    println!("Found MX subdomain: {}", hostname);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            if verbose {
                println!("Error looking up NS records: {}", e);
            }
        }
    }

    // Try to find CNAME records for common WWW
    let www_domain = format!("www.{}", domain);
    if let Ok(cname_lookup) = resolver.lookup(&www_domain, RecordType::CNAME).await {
        for cname in cname_lookup.iter() {
            let cname_str = cname.to_string();
            if cname_str.ends_with(domain) && cname_str != domain {
                subdomains.insert(cname_str.clone());
                if verbose {
                    println!("Found CNAME subdomain: {}", cname_str);
                }
            }
        }
    }

    if verbose {
        println!(
            "Found {} subdomains via DNS-based enumeration",
            subdomains.len()
        );
    }

    Ok(subdomains)
}

/// Checks a subdomain endpoint for responsiveness
pub async fn check_api_endpoint(client: &Client, target: &str, verbose: bool) -> bool {
    // Add timeout to the HTTP request
    match timeout(Duration::from_secs(10), client.get(target).send()).await {
        Ok(Ok(response)) => {
            let status = response.status();
            if verbose {
                println!("Response from {}: {}", target, status);
            }
            status.is_success() || status.as_u16() == 401 || status.as_u16() == 403
        }
        Ok(Err(e)) => {
            if verbose {
                println!("Error connecting to {}: {}", target, e);
            }
            false
        }
        Err(_) => {
            if verbose {
                println!("Timeout connecting to {}", target);
            }
            false
        }
    }
}
