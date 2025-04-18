use chrono::Local;
use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::PathBuf;
use std::process;

mod config;
mod exploits;
mod report;
mod scanners;
mod utils;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run an automated vulnerability scan
    Scan {
        /// Target to scan (IP address, hostname, or URL)
        #[arg(short, long)]
        target: String,

        /// Type of scan to perform
        #[arg(short, long, default_value = "basic")]
        #[clap(value_enum)]
        scan_type: ScanType,

        /// Output file for scan results
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Enable subdomain discovery and scanning
        #[arg(long, default_value = "false")]
        scan_subdomains: bool,
    },
    /// Attempt to exploit found vulnerabilities
    Exploit {
        /// Target to exploit
        #[arg(short, long)]
        target: String,

        /// Vulnerability ID to exploit
        #[arg(short, long)]
        vuln_id: Option<String>,

        /// Safe mode (non-destructive exploits only)
        #[arg(short, long, default_value = "true")]
        safe_mode: bool,

        /// Path to scan results file (optional, otherwise will try to find or create)
        #[arg(short, long)]
        scan_file: Option<PathBuf>,

        /// Output file for exploitation results
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Generate report after exploitation completes
        #[arg(long)]
        generate_report: bool,
    },
    /// Generate a report from scan results
    Report {
        /// Input file with scan results
        #[arg(short, long)]
        input: PathBuf,

        /// Output file for the report
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Interactive mode
    Interactive,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ScanType {
    Basic,
    Network,
    Web,
    Vuln,
    SSL,
    Full,
}

fn print_banner() {
    println!(
        "{}",
        r#"
███████╗ ██████╗ ██████╗ ████████╗██╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝██╔═══██╗██╔══██╗██╔════╝
█████╗  ██║   ██║██████╔╝   ██║   ██║██║     ██║   ██║██████╔╝█████╗  
██╔══╝  ██║   ██║██╔══██╗   ██║   ██║██║     ██║   ██║██╔══██╗██╔══╝  
██║     ╚██████╔╝██║  ██║   ██║   ██║╚██████╗╚██████╔╝██║  ██║███████╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
                                                 
    "#
        .bright_red()
    );
    println!("{}", "Penetration Testing Tool".bright_blue());
    println!("{}", "Version 0.1.0".bright_yellow());
    println!();
}

// Add this function to create a default output path for scans
fn create_default_output_path(target: &str, scan_type: &ScanType) -> Option<PathBuf> {
    // Create a 'scans' folder in the current directory where the program is run
    let scans_dir = PathBuf::from("./scans");

    // Create directory if it doesn't exist
    if try_create_dir(&scans_dir) {
        return create_scan_file(&scans_dir, target, scan_type);
    }

    // Fall back to user's home directory if local directory creation fails
    if let Some(home_dir) = dirs::home_dir() {
        let user_scans_dir = home_dir.join(".forticore").join("scans");
        if try_create_dir(&user_scans_dir) {
            return create_scan_file(&user_scans_dir, target, scan_type);
        }
    }

    // Last resort - try system directory
    let system_scans_dir = PathBuf::from("/var/lib/forticore/scans");
    if try_create_dir(&system_scans_dir) {
        return create_scan_file(&system_scans_dir, target, scan_type);
    }

    None
}

fn try_create_dir(dir: &PathBuf) -> bool {
    match fs::create_dir_all(dir) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn create_scan_file(dir: &PathBuf, target: &str, scan_type: &ScanType) -> Option<PathBuf> {
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let filename = format!(
        "{}_{:?}_{}.json",
        target.replace(".", "_"),
        scan_type,
        timestamp
    );
    Some(dir.join(filename))
}

#[tokio::main]
async fn main() {
    env_logger::init();
    print_banner();

    // Ensure scans directory exists
    let scans_dir = PathBuf::from("./scans");
    if let Err(e) = fs::create_dir_all(&scans_dir) {
        eprintln!("Warning: Failed to create scans directory: {}", e);
    }

    let cli = Cli::parse();

    if cli.verbose {
        println!("{}", "Verbose mode enabled".bright_green());
    }

    match &cli.command {
        Some(Commands::Scan {
            target,
            scan_type,
            output,
            scan_subdomains,
        }) => {
            println!(
                "{} {} with scan type: {:?}",
                "Scanning target:".bright_yellow(),
                target.bright_white(),
                scan_type
            );

            // Use the provided output path or create a default one
            let output_path = output.as_ref().cloned().or_else(|| {
                let default_path = create_default_output_path(target, scan_type);
                if cli.verbose && default_path.is_some() {
                    println!(
                        "{} {}",
                        "No output file specified. Using default path:".bright_yellow(),
                        default_path
                            .as_ref()
                            .unwrap()
                            .display()
                            .to_string()
                            .bright_white()
                    );
                } else if default_path.is_some() {
                    println!(
                        "{} {}",
                        "Scan results will be saved to:".bright_green(),
                        default_path
                            .as_ref()
                            .unwrap()
                            .display()
                            .to_string()
                            .bright_white()
                    );
                }
                default_path
            });

            match scanners::run_scan(
                target,
                scan_type,
                output_path.as_deref(),
                cli.verbose,
                *scan_subdomains,
            )
            .await
            {
                Ok(_) => {
                    if let Some(path) = &output_path {
                        println!(
                            "{} {}",
                            "Scan results saved to:".bright_green(),
                            path.display().to_string().bright_white()
                        );
                    }
                    println!("{}", "Scan completed successfully".bright_green())
                }
                Err(e) => {
                    eprintln!("{} {}", "Error during scan:".bright_red(), e);
                    process::exit(1);
                }
            }
        }
        Some(Commands::Exploit {
            target,
            vuln_id,
            safe_mode,
            scan_file,
            output,
            generate_report,
        }) => {
            println!(
                "{} {}",
                "Exploiting target:".bright_yellow(),
                target.bright_white()
            );
            if let Some(id) = vuln_id {
                println!(
                    "{} {}",
                    "Targeting vulnerability ID:".bright_yellow(),
                    id.bright_white()
                );
            }
            println!(
                "{} {}",
                "Safe mode:".bright_yellow(),
                safe_mode.to_string().bright_white()
            );

            match exploits::run_exploit(
                target,
                vuln_id.as_deref(),
                *safe_mode,
                cli.verbose,
                scan_file.as_deref(),
                output.as_deref(),
            )
            .await
            {
                Ok(_) => {
                    println!("{}", "Exploitation completed".bright_green());

                    // Generate report if requested and we have an output file
                    if *generate_report && output.is_some() {
                        let output_path = output.as_ref().unwrap();
                        let report_filename =
                            format!("{}.pdf", output_path.file_stem().unwrap().to_str().unwrap());
                        let report_path = output_path.with_file_name(report_filename);

                        println!(
                            "{} {} to {}",
                            "Generating report from:".bright_yellow(),
                            output_path.display().to_string().bright_white(),
                            report_path.display().to_string().bright_white()
                        );

                        match report::generate_report(output_path, &report_path, cli.verbose) {
                            Ok(_) => println!("{}", "Report generated successfully".bright_green()),
                            Err(e) => {
                                eprintln!("{} {}", "Error generating report:".bright_red(), e);
                                process::exit(1);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Error during exploitation:".bright_red(), e);
                    process::exit(1);
                }
            }
        }
        Some(Commands::Report { input, output }) => {
            println!(
                "{} {} to {}",
                "Generating report from:".bright_yellow(),
                input.display().to_string().bright_white(),
                output.display().to_string().bright_white()
            );

            match report::generate_report(input, output, cli.verbose) {
                Ok(_) => println!("{}", "Report generated successfully".bright_green()),
                Err(e) => {
                    eprintln!("{} {}", "Error generating report:".bright_red(), e);
                    process::exit(1);
                }
            }
        }
        Some(Commands::Interactive) => {
            println!("{}", "Starting interactive mode...".bright_green());
            // TODO: Implement interactive mode
            println!("{}", "Interactive mode not yet implemented".bright_yellow());
        }
        None => {
            println!(
                "{}",
                "No command specified. Use --help for usage information.".bright_yellow()
            );
            println!(
                "{}",
                "Starting interactive mode by default...".bright_green()
            );
            // TODO: Implement interactive mode
            println!("{}", "Interactive mode not yet implemented".bright_yellow());
        }
    }
}
