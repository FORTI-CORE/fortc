mod pdf_generator;

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

                // Add details if available
                if !vuln.details.is_null() {
                    writeln!(file, "   Details:")?;

                    if let Some(obj) = vuln.details.as_object() {
                        for (key, value) in obj {
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
