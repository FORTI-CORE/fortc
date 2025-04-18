mod pdf_generator;

use crate::exploits::ExploitResult;
use crate::scanners::{Severity, Vulnerability};
use crate::utils::{error::FortiCoreResult, FortiCoreError};
use chrono::Local;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn generate_report(
    input_path: &Path,
    output_path: &Path,
    verbose: bool,
) -> FortiCoreResult<()> {
    if verbose {
        println!(
            "Generating report from {} to {}",
            input_path.display(),
            output_path.display()
        );
    }

    // Read the input file
    let vulnerabilities = read_vulnerabilities(input_path)?;

    if verbose {
        println!(
            "Read {} vulnerabilities from input file",
            vulnerabilities.len()
        );
    }

    // Generate the report
    match output_path.extension().and_then(|ext| ext.to_str()) {
        Some("pdf") => {
            pdf_generator::generate_pdf_report(&vulnerabilities, output_path, verbose)?;
        }
        Some("txt") | None => {
            generate_text_report(&vulnerabilities, output_path, verbose)?;
        }
        Some(ext) => {
            return Err(FortiCoreError::ReportError(format!(
                "Unsupported report format: {}",
                ext
            )));
        }
    }

    if verbose {
        println!("Report generated successfully");
    }

    Ok(())
}

fn read_vulnerabilities(path: &Path) -> FortiCoreResult<Vec<Vulnerability>> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Try parsing as an array of vulnerabilities directly first
    let result: Result<Vec<Vulnerability>, _> = serde_json::from_str(&contents);

    if let Ok(vulns) = result {
        return Ok(vulns);
    }

    // If that didn't work, try parsing as a scan result object with a vulnerabilities field
    #[derive(Deserialize)]
    struct ScanResultWrapper {
        vulnerabilities: Vec<Vulnerability>,
    }

    let result: Result<ScanResultWrapper, _> = serde_json::from_str(&contents);

    if let Ok(wrapper) = result {
        return Ok(wrapper.vulnerabilities);
    }

    // Try parsing as exploit results
    let result: Result<serde_json::Value, _> = serde_json::from_str(&contents);
    if let Ok(json_value) = result {
        // Check if this is an exploit result file
        if let Some(results) = json_value.get("results").and_then(|r| r.as_array()) {
            let vulns = convert_exploit_results_to_vulnerabilities(results)?;
            return Ok(vulns);
        }
    }

    // If that didn't work either, try a more flexible approach
    let json_value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|e| FortiCoreError::SerializationError(e))?;

    if let Some(vulns) = json_value.get("vulnerabilities").and_then(|v| v.as_array()) {
        let vulns: Result<Vec<Vulnerability>, _> = serde_json::from_value(vulns.clone().into());
        if let Ok(parsed_vulns) = vulns {
            return Ok(parsed_vulns);
        }
    }

    // Return empty result if we couldn't parse any vulnerabilities
    Ok(Vec::new())
}

// Convert exploit results to vulnerabilities for reporting
fn convert_exploit_results_to_vulnerabilities(
    exploit_results: &[serde_json::Value],
) -> FortiCoreResult<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();

    for result in exploit_results {
        // Skip if not a valid structure
        if !result.is_object() {
            continue;
        }

        // Extract vulnerability based on result type
        if let Some(success) = result.get("Success") {
            if let Some(vuln) = success.get("vulnerability") {
                let vuln: Vulnerability = serde_json::from_value(vuln.clone())?;

                // Include exploitation details
                let mut vuln_with_details = vuln.clone();
                if let Some(details) = success.get("details") {
                    vuln_with_details.details = details.clone();
                    // Add exploitation status
                    if vuln_with_details.details.is_object() {
                        let mut details_obj =
                            vuln_with_details.details.as_object().unwrap().clone();
                        details_obj.insert(
                            "exploitation_status".to_string(),
                            serde_json::Value::String("Success".to_string()),
                        );
                        vuln_with_details.details = serde_json::Value::Object(details_obj);
                    }
                }

                vulnerabilities.push(vuln_with_details);
            }
        } else if let Some(partial) = result.get("Partial") {
            if let Some(vuln) = partial.get("vulnerability") {
                let vuln: Vulnerability = serde_json::from_value(vuln.clone())?;

                // Include exploitation details
                let mut vuln_with_details = vuln.clone();
                if let Some(details) = partial.get("details") {
                    vuln_with_details.details = details.clone();
                    // Add exploitation status and reason
                    if vuln_with_details.details.is_object() {
                        let mut details_obj =
                            vuln_with_details.details.as_object().unwrap().clone();
                        details_obj.insert(
                            "exploitation_status".to_string(),
                            serde_json::Value::String("Partial".to_string()),
                        );
                        if let Some(reason) = partial.get("reason") {
                            details_obj.insert("reason".to_string(), reason.clone());
                        }
                        vuln_with_details.details = serde_json::Value::Object(details_obj);
                    }
                }

                vulnerabilities.push(vuln_with_details);
            }
        } else if let Some(failed) = result.get("Failed") {
            if let Some(vuln) = failed.get("vulnerability") {
                let vuln: Vulnerability = serde_json::from_value(vuln.clone())?;

                // Include exploitation details
                let mut vuln_with_details = vuln.clone();
                // Add exploitation status and reason
                let mut details_obj = if vuln_with_details.details.is_object() {
                    vuln_with_details.details.as_object().unwrap().clone()
                } else {
                    serde_json::Map::new()
                };

                details_obj.insert(
                    "exploitation_status".to_string(),
                    serde_json::Value::String("Failed".to_string()),
                );
                if let Some(reason) = failed.get("reason") {
                    details_obj.insert("reason".to_string(), reason.clone());
                }
                vuln_with_details.details = serde_json::Value::Object(details_obj);

                vulnerabilities.push(vuln_with_details);
            }
        }
    }

    Ok(vulnerabilities)
}

fn generate_text_report(
    vulnerabilities: &[Vulnerability],
    output_path: &Path,
    verbose: bool,
) -> FortiCoreResult<()> {
    use std::io::Write;

    if verbose {
        println!("Generating text report");
    }

    let mut file = File::create(output_path)?;

    // Write report header
    writeln!(file, "FortiCore Security Report")?;
    writeln!(file, "=========================")?;
    writeln!(file, "Date: {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file, "Number of findings: {}", vulnerabilities.len())?;
    writeln!(file, "=========================")?;
    writeln!(file)?;

    // Group vulnerabilities by severity
    let mut by_severity = vec![
        Vec::new(), // Info
        Vec::new(), // Low
        Vec::new(), // Medium
        Vec::new(), // High
        Vec::new(), // Critical
    ];

    for vuln in vulnerabilities {
        let index = match vuln.severity {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };

        by_severity[index].push(vuln);
    }

    // Summary section
    writeln!(file, "SUMMARY")?;
    writeln!(file, "=======")?;
    writeln!(file, "Critical: {}", by_severity[4].len())?;
    writeln!(file, "High: {}", by_severity[3].len())?;
    writeln!(file, "Medium: {}", by_severity[2].len())?;
    writeln!(file, "Low: {}", by_severity[1].len())?;
    writeln!(file, "Info: {}", by_severity[0].len())?;
    writeln!(file)?;

    // Check if we have exploitation data
    let has_exploit_data = vulnerabilities.iter().any(|v| {
        if let Some(obj) = v.details.as_object() {
            obj.contains_key("exploitation_status")
        } else {
            false
        }
    });

    // Exploitation summary if available
    if has_exploit_data {
        let successful = vulnerabilities
            .iter()
            .filter(|v| {
                if let Some(obj) = v.details.as_object() {
                    if let Some(status) = obj.get("exploitation_status").and_then(|s| s.as_str()) {
                        return status == "Success";
                    }
                }
                false
            })
            .count();

        let partial = vulnerabilities
            .iter()
            .filter(|v| {
                if let Some(obj) = v.details.as_object() {
                    if let Some(status) = obj.get("exploitation_status").and_then(|s| s.as_str()) {
                        return status == "Partial";
                    }
                }
                false
            })
            .count();

        let failed = vulnerabilities
            .iter()
            .filter(|v| {
                if let Some(obj) = v.details.as_object() {
                    if let Some(status) = obj.get("exploitation_status").and_then(|s| s.as_str()) {
                        return status == "Failed";
                    }
                }
                false
            })
            .count();

        writeln!(file, "EXPLOITATION SUMMARY")?;
        writeln!(file, "====================")?;
        writeln!(file, "Successfully Exploited: {}", successful)?;
        writeln!(file, "Partially Exploited: {}", partial)?;
        writeln!(file, "Failed Exploitation: {}", failed)?;
        writeln!(file)?;
    }

    // Detailed findings
    writeln!(file, "DETAILED FINDINGS")?;
    writeln!(file, "=================")?;

    // Start with highest severity
    for severity_level in (0..=4).rev() {
        let severity_name = match severity_level {
            0 => "INFO",
            1 => "LOW",
            2 => "MEDIUM",
            3 => "HIGH",
            4 => "CRITICAL",
            _ => unreachable!(),
        };

        if !by_severity[severity_level].is_empty() {
            writeln!(file, "\n{} Severity Findings", severity_name)?;
            writeln!(file, "{}", "-".repeat(severity_name.len() + 18))?;

            for (i, vuln) in by_severity[severity_level].iter().enumerate() {
                writeln!(file, "\n{}. {} ({})", i + 1, vuln.name, vuln.id)?;
                writeln!(file, "   Location: {}", vuln.location)?;
                writeln!(file, "   Description: {}", vuln.description)?;
                writeln!(
                    file,
                    "   Exploitable: {}",
                    if vuln.exploitable { "Yes" } else { "No" }
                )?;

                // Add exploitation status if available
                if let Some(obj) = vuln.details.as_object() {
                    if let Some(status) = obj.get("exploitation_status").and_then(|s| s.as_str()) {
                        writeln!(file, "   Exploitation Status: {}", status)?;

                        // If there's a reason for failure or partial success, include it
                        if let Some(reason) = obj.get("reason").and_then(|r| r.as_str()) {
                            writeln!(file, "   Exploitation Result: {}", reason)?;
                        }
                    }
                }

                // Add details if available
                if !vuln.details.is_null() {
                    writeln!(file, "   Details:")?;

                    if let Some(obj) = vuln.details.as_object() {
                        for (key, value) in obj {
                            // Skip these keys as they're already displayed separately
                            if key == "exploitation_status" || key == "reason" {
                                continue;
                            }

                            let value_str = match value {
                                serde_json::Value::String(s) => s.clone(),
                                _ => value.to_string(),
                            };

                            writeln!(file, "     - {}: {}", key, value_str)?;
                        }
                    }
                }

                // Recommendations (example)
                writeln!(
                    file,
                    "   Recommendation: Patch or mitigate this vulnerability as appropriate"
                )?;
            }
        }
    }

    // Footer with disclaimer
    writeln!(file, "\n\nDISCLAIMER")?;
    writeln!(file, "==========")?;
    writeln!(
        file,
        "This report was generated automatically by FortiCore."
    )?;
    writeln!(file, "The findings in this report should be verified by security professionals before taking action.")?;
    writeln!(
        file,
        "FortiCore is provided 'as is' without warranty of any kind."
    )?;

    if verbose {
        println!("Text report generated successfully");
    }

    Ok(())
}
