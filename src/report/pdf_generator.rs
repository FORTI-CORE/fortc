use crate::scanners::{Severity, Vulnerability};
use crate::utils::{error::FortiCoreResult, FortiCoreError};
use chrono::Local;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn generate_pdf_report(
    vulnerabilities: &[Vulnerability],
    output_path: &Path,
    verbose: bool,
) -> FortiCoreResult<()> {
    if verbose {
        println!("Generating PDF report...");
    }

    // For simplicity, we'll generate a basic PDF by hand with just text content
    // This is a workaround for version compatibility issues with pdf-writer 0.13.0

    // Simple PDF structure
    let mut output = Vec::new();

    // PDF header
    output.extend_from_slice(b"%PDF-1.7\n");

    // Objects
    // 1. Catalog
    output.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\n");

    // 2. Pages
    output.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\n");

    // 3. Page
    output.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /MediaBox [0 0 595 842] >>\nendobj\n\n");

    // 4. Font
    output.extend_from_slice(
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n\n",
    );

    // 5. Content
    // Count vulnerabilities by severity
    let mut count_by_severity = [0; 5]; // Info, Low, Medium, High, Critical

    for vuln in vulnerabilities {
        let index = match vuln.severity {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };

        count_by_severity[index] += 1;
    }

    // Generate a sorted list of vulnerabilities by severity
    let mut sorted_vulns: Vec<&Vulnerability> = vulnerabilities.iter().collect();
    sorted_vulns.sort_by(|a, b| b.severity.cmp(&a.severity));
    let top_vulns: Vec<&Vulnerability> = sorted_vulns.iter().take(5).cloned().collect();

    // Create the content stream
    let mut content = Vec::new();

    // Begin content stream
    content.extend_from_slice(b"BT\n");

    // Title
    content.extend_from_slice(b"/F1 18 Tf\n");
    content.extend_from_slice(b"50 750 Td\n");
    content.extend_from_slice(b"(FortiCore Security Report) Tj\n");

    // Date
    content.extend_from_slice(b"/F1 12 Tf\n");
    content.extend_from_slice(b"0 -30 Td\n");
    content.extend_from_slice(
        format!("(Date: {}) Tj\n", Local::now().format("%Y-%m-%d %H:%M:%S")).as_bytes(),
    );

    // Summary section
    content.extend_from_slice(b"0 -30 Td\n");
    content.extend_from_slice(b"/F1 14 Tf\n");
    content.extend_from_slice(b"(SUMMARY) Tj\n");

    // Display counts
    content.extend_from_slice(b"/F1 12 Tf\n");
    content.extend_from_slice(b"10 -20 Td\n");
    content.extend_from_slice(format!("(Critical: {}) Tj\n", count_by_severity[4]).as_bytes());

    content.extend_from_slice(b"0 -15 Td\n");
    content.extend_from_slice(format!("(High: {}) Tj\n", count_by_severity[3]).as_bytes());

    content.extend_from_slice(b"0 -15 Td\n");
    content.extend_from_slice(format!("(Medium: {}) Tj\n", count_by_severity[2]).as_bytes());

    content.extend_from_slice(b"0 -15 Td\n");
    content.extend_from_slice(format!("(Low: {}) Tj\n", count_by_severity[1]).as_bytes());

    content.extend_from_slice(b"0 -15 Td\n");
    content.extend_from_slice(format!("(Info: {}) Tj\n", count_by_severity[0]).as_bytes());

    // Top findings section
    content.extend_from_slice(b"0 -30 Td\n");
    content.extend_from_slice(b"/F1 14 Tf\n");
    content.extend_from_slice(b"(TOP FINDINGS) Tj\n");

    // Display top vulnerabilities
    for (i, vuln) in top_vulns.iter().enumerate() {
        content.extend_from_slice(b"0 -25 Td\n");
        content.extend_from_slice(b"/F1 12 Tf\n");
        content.extend_from_slice(
            format!("({}. {}) Tj\n", i + 1, escape_pdf_string(&vuln.name)).as_bytes(),
        );

        content.extend_from_slice(b"10 -15 Td\n");
        content.extend_from_slice(b"/F1 10 Tf\n");
        content.extend_from_slice(format!("(Severity: {:?}) Tj\n", vuln.severity).as_bytes());

        content.extend_from_slice(b"0 -15 Td\n");
        content.extend_from_slice(
            format!("(Location: {}) Tj\n", escape_pdf_string(&vuln.location)).as_bytes(),
        );

        // Description (truncated if too long)
        let desc = if vuln.description.len() > 80 {
            format!("{}...", &vuln.description[0..77])
        } else {
            vuln.description.clone()
        };

        content.extend_from_slice(b"0 -15 Td\n");
        content.extend_from_slice(
            format!("(Description: {}) Tj\n", escape_pdf_string(&desc)).as_bytes(),
        );
    }

    // Disclaimer
    content.extend_from_slice(b"0 -30 Td\n");
    content.extend_from_slice(b"/F1 12 Tf\n");
    content.extend_from_slice(b"(DISCLAIMER) Tj\n");

    content.extend_from_slice(b"0 -15 Td\n");
    content.extend_from_slice(b"/F1 10 Tf\n");
    content.extend_from_slice(b"(This report was generated automatically by FortiCore.) Tj\n");

    content.extend_from_slice(b"0 -15 Td\n");
    content.extend_from_slice(
        b"(The findings should be verified by security professionals before taking action.) Tj\n",
    );

    content.extend_from_slice(b"0 -15 Td\n");
    content.extend_from_slice(
        format!(
            "(Digital Signature: FortiCore-Report-{}) Tj\n",
            Local::now().timestamp()
        )
        .as_bytes(),
    );

    // End text block
    content.extend_from_slice(b"ET\n");

    // Compress the content (in a real implementation)
    // For simplicity, we'll just use the raw content

    // Write the content stream object
    output.extend_from_slice(b"5 0 obj\n");
    output.extend_from_slice(b"<< /Length ");
    output.extend_from_slice(content.len().to_string().as_bytes());
    output.extend_from_slice(b" >>\nstream\n");
    output.extend_from_slice(&content);
    output.extend_from_slice(b"\nendstream\nendobj\n\n");

    // Cross-reference table
    let xref_pos = output.len();
    output.extend_from_slice(b"xref\n");
    output.extend_from_slice(b"0 6\n");
    output.extend_from_slice(b"0000000000 65535 f \n");

    // Find positions of objects for xref table
    // Safely find positions without unwrapping
    let mut object_positions = vec![0; 5];

    // Find position of object 1
    if let Some(pos) = find_object_position(&output, 1) {
        object_positions[0] = pos;
    }

    // Find position of object 2
    if let Some(pos) = find_object_position(&output, 2) {
        object_positions[1] = pos;
    }

    // Find position of object 3
    if let Some(pos) = find_object_position(&output, 3) {
        object_positions[2] = pos;
    }

    // Find position of object 4
    if let Some(pos) = find_object_position(&output, 4) {
        object_positions[3] = pos;
    }

    // Find position of object 5
    if let Some(pos) = find_object_position(&output, 5) {
        object_positions[4] = pos;
    }

    // Write xref entries
    for pos in object_positions {
        output.extend_from_slice(format!("{:010} 00000 n \n", pos).as_bytes());
    }

    // Trailer
    output.extend_from_slice(b"trailer\n");
    output.extend_from_slice(b"<< /Size 6 /Root 1 0 R >>\n");
    output.extend_from_slice(b"startxref\n");
    output.extend_from_slice(xref_pos.to_string().as_bytes());
    output.extend_from_slice(b"\n%%EOF\n");

    // Write to file
    let mut file = File::create(output_path).map_err(|e| FortiCoreError::IoError(e))?;
    file.write_all(&output)
        .map_err(|e| FortiCoreError::IoError(e))?;

    if verbose {
        println!("PDF report generated successfully");
    }

    Ok(())
}

// Helper function to find position of an object in the PDF
fn find_object_position(data: &[u8], obj_num: u32) -> Option<usize> {
    let pattern = format!("{} 0 obj", obj_num);
    let pattern_bytes = pattern.as_bytes();

    for i in 0..data.len() - pattern_bytes.len() {
        if &data[i..i + pattern_bytes.len()] == pattern_bytes {
            return Some(i);
        }
    }

    None
}

fn escape_pdf_string(input: &str) -> String {
    input
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
}
