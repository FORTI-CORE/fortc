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

            match exploits::run_exploit(target, vuln_id.as_deref(), *safe_mode, cli.verbose).await {
                Ok(_) => println!("{}", "Exploitation completed".bright_green()),
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
            run_interactive_mode(cli.verbose).await;
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
            run_interactive_mode(cli.verbose).await;
        }
    }
}

/// Run interactive mode with a menu-based interface
async fn run_interactive_mode(verbose: bool) {
    use std::io::{self, Write};

    loop {
        println!("\n{}", "=== FortiCore Interactive Mode ===".bright_cyan());
        println!("1. {}", "Run a scan".bright_green());
        println!("2. {}", "Exploit vulnerabilities".bright_yellow());
        println!("3. {}", "Generate a report".bright_blue());
        println!("4. {}", "Configure settings".bright_magenta());
        println!("0. {}", "Exit".bright_red());

        print!("\n{}", "Enter your choice: ".bright_white());
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin()
            .read_line(&mut choice)
            .expect("Failed to read input");

        match choice.trim() {
            "1" => interactive_scan_menu(verbose).await,
            "2" => interactive_exploit_menu(verbose).await,
            "3" => interactive_report_menu(verbose).await,
            "4" => interactive_config_menu(verbose).await,
            "0" => {
                println!("{}", "Exiting FortiCore. Goodbye!".bright_green());
                break;
            }
            _ => println!("{}", "Invalid choice. Please try again.".bright_red()),
        }
    }
}

/// Interactive scan menu
async fn interactive_scan_menu(verbose: bool) {
    use std::io::{self, Write};
    use std::path::PathBuf;

    println!("\n{}", "=== Scan Options ===".bright_cyan());

    // Get target
    print!("{}", "Enter target (IP, domain, or URL): ".bright_white());
    io::stdout().flush().unwrap();
    let mut target = String::new();
    io::stdin()
        .read_line(&mut target)
        .expect("Failed to read input");
    let target = target.trim().to_string();

    if target.is_empty() {
        println!(
            "{}",
            "Target cannot be empty. Returning to main menu.".bright_red()
        );
        return;
    }

    // Get scan type
    println!("\n{}", "Scan Types:".bright_yellow());
    println!("1. Basic");
    println!("2. Network");
    println!("3. Web");
    println!("4. Vulnerability");
    println!("5. SSL/TLS");
    println!("6. Full (comprehensive scan)");

    print!("\n{}", "Choose scan type [1-6]: ".bright_white());
    io::stdout().flush().unwrap();
    let mut scan_type_choice = String::new();
    io::stdin()
        .read_line(&mut scan_type_choice)
        .expect("Failed to read input");

    let scan_type = match scan_type_choice.trim() {
        "1" => ScanType::Basic,
        "2" => ScanType::Network,
        "3" => ScanType::Web,
        "4" => ScanType::Vuln,
        "5" => ScanType::SSL,
        "6" => ScanType::Full,
        _ => {
            println!(
                "{}",
                "Invalid choice. Using Basic scan type.".bright_yellow()
            );
            ScanType::Basic
        }
    };

    // Subdomain scanning option (for Web scans)
    let scan_subdomains = if matches!(scan_type, ScanType::Web | ScanType::Full) {
        print!("{}", "Enable subdomain scanning? (y/n): ".bright_white());
        io::stdout().flush().unwrap();
        let mut subdomain_choice = String::new();
        io::stdin()
            .read_line(&mut subdomain_choice)
            .expect("Failed to read input");
        subdomain_choice.trim().to_lowercase().starts_with('y')
    } else {
        false
    };

    // Get output path
    print!(
        "{}",
        "Enter output file path (leave empty for default): ".bright_white()
    );
    io::stdout().flush().unwrap();
    let mut output_path = String::new();
    io::stdin()
        .read_line(&mut output_path)
        .expect("Failed to read input");
    let output_path = output_path.trim();

    let output_option = if output_path.is_empty() {
        create_default_output_path(&target, &scan_type)
    } else {
        Some(PathBuf::from(output_path))
    };

    // Confirm scan details
    println!("\n{}", "=== Scan Summary ===".bright_blue());
    println!("Target: {}", target.bright_white());
    println!("Scan Type: {:?}", scan_type);
    println!("Subdomain Scanning: {}", scan_subdomains);
    if let Some(path) = &output_option {
        println!("Output File: {}", path.display().to_string().bright_white());
    } else {
        println!("Output: {}", "No output file".bright_yellow());
    }

    print!("\n{}", "Start scan? (y/n): ".bright_white());
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin()
        .read_line(&mut confirm)
        .expect("Failed to read input");

    if confirm.trim().to_lowercase().starts_with('y') {
        println!("{}", "Starting scan...".bright_green());

        match scanners::run_scan(
            &target,
            &scan_type,
            output_option.as_deref(),
            verbose,
            scan_subdomains,
        )
        .await
        {
            Ok(_) => {
                if let Some(path) = &output_option {
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
            }
        }
    } else {
        println!("{}", "Scan cancelled.".bright_yellow());
    }
}

/// Interactive exploit menu
async fn interactive_exploit_menu(verbose: bool) {
    use std::io::{self, Write};

    println!("\n{}", "=== Exploit Options ===".bright_cyan());

    // Get target
    print!("{}", "Enter target (IP, domain, or URL): ".bright_white());
    io::stdout().flush().unwrap();
    let mut target = String::new();
    io::stdin()
        .read_line(&mut target)
        .expect("Failed to read input");
    let target = target.trim().to_string();

    if target.is_empty() {
        println!(
            "{}",
            "Target cannot be empty. Returning to main menu.".bright_red()
        );
        return;
    }

    // Get vulnerability ID (optional)
    print!(
        "{}",
        "Enter vulnerability ID (leave empty for auto-detection): ".bright_white()
    );
    io::stdout().flush().unwrap();
    let mut vuln_id = String::new();
    io::stdin()
        .read_line(&mut vuln_id)
        .expect("Failed to read input");
    let vuln_id = vuln_id.trim();
    let vuln_id_option = if vuln_id.is_empty() {
        None
    } else {
        Some(vuln_id.to_string())
    };

    // Safe mode option
    print!(
        "{}",
        "Enable safe mode? (y/n) [default: y]: ".bright_white()
    );
    io::stdout().flush().unwrap();
    let mut safe_mode_choice = String::new();
    io::stdin()
        .read_line(&mut safe_mode_choice)
        .expect("Failed to read input");
    let safe_mode = !safe_mode_choice.trim().to_lowercase().starts_with('n');

    // Confirm exploit details
    println!("\n{}", "=== Exploit Summary ===".bright_blue());
    println!("Target: {}", target.bright_white());
    if let Some(id) = &vuln_id_option {
        println!("Vulnerability ID: {}", id.bright_white());
    } else {
        println!("Vulnerability ID: {}", "Auto-detect".bright_yellow());
    }
    println!("Safe Mode: {}", safe_mode.to_string().bright_white());

    print!("\n{}", "Start exploitation? (y/n): ".bright_white());
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin()
        .read_line(&mut confirm)
        .expect("Failed to read input");

    if confirm.trim().to_lowercase().starts_with('y') {
        println!("{}", "Starting exploitation...".bright_green());

        match exploits::run_exploit(&target, vuln_id_option.as_deref(), safe_mode, verbose).await {
            Ok(_) => println!("{}", "Exploitation completed".bright_green()),
            Err(e) => {
                eprintln!("{} {}", "Error during exploitation:".bright_red(), e);
            }
        }
    } else {
        println!("{}", "Exploitation cancelled.".bright_yellow());
    }
}

/// Interactive report menu
async fn interactive_report_menu(verbose: bool) {
    use std::io::{self, Write};
    use std::path::PathBuf;

    println!("\n{}", "=== Report Options ===".bright_cyan());

    // Get input file
    print!(
        "{}",
        "Enter input file path (scan results): ".bright_white()
    );
    io::stdout().flush().unwrap();
    let mut input_path = String::new();
    io::stdin()
        .read_line(&mut input_path)
        .expect("Failed to read input");
    let input_path = input_path.trim().to_string();

    if input_path.is_empty() {
        println!(
            "{}",
            "Input file path cannot be empty. Returning to main menu.".bright_red()
        );
        return;
    }

    // Get output file
    print!(
        "{}",
        "Enter output file path (report file): ".bright_white()
    );
    io::stdout().flush().unwrap();
    let mut output_path = String::new();
    io::stdin()
        .read_line(&mut output_path)
        .expect("Failed to read input");
    let output_path = output_path.trim().to_string();

    if output_path.is_empty() {
        println!(
            "{}",
            "Output file path cannot be empty. Returning to main menu.".bright_red()
        );
        return;
    }

    // Confirm report details
    println!("\n{}", "=== Report Summary ===".bright_blue());
    println!("Input File: {}", input_path.bright_white());
    println!("Output File: {}", output_path.bright_white());

    print!("\n{}", "Generate report? (y/n): ".bright_white());
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin()
        .read_line(&mut confirm)
        .expect("Failed to read input");

    if confirm.trim().to_lowercase().starts_with('y') {
        println!("{}", "Generating report...".bright_green());

        match report::generate_report(
            &PathBuf::from(input_path),
            &PathBuf::from(output_path),
            verbose,
        ) {
            Ok(_) => println!("{}", "Report generated successfully".bright_green()),
            Err(e) => {
                eprintln!("{} {}", "Error generating report:".bright_red(), e);
            }
        }
    } else {
        println!("{}", "Report generation cancelled.".bright_yellow());
    }
}

/// Interactive configuration menu
async fn interactive_config_menu(verbose: bool) {
    use std::io::{self, Write};

    println!("\n{}", "=== Configuration Options ===".bright_cyan());
    println!("1. {}", "View current configuration".bright_green());
    println!("2. {}", "Configure API keys".bright_yellow());
    println!("3. {}", "Configure scan defaults".bright_blue());
    println!("0. {}", "Back to main menu".bright_red());

    print!("\n{}", "Enter your choice: ".bright_white());
    io::stdout().flush().unwrap();

    let mut choice = String::new();
    io::stdin()
        .read_line(&mut choice)
        .expect("Failed to read input");

    match choice.trim() {
        "1" => {
            println!("{}", "Viewing current configuration...".bright_green());
            match config::show_config(verbose) {
                Ok(_) => {}
                Err(e) => eprintln!("{} {}", "Error showing configuration:".bright_red(), e),
            }
        }
        "2" => {
            interactive_api_key_config(verbose).await;
        }
        "3" => {
            interactive_scan_defaults_config(verbose).await;
        }
        "0" => {
            println!("{}", "Returning to main menu.".bright_yellow());
        }
        _ => println!("{}", "Invalid choice. Returning to main menu.".bright_red()),
    }
}

/// Interactive API key configuration
async fn interactive_api_key_config(verbose: bool) {
    use std::io::{self, Write};

    println!("\n{}", "=== API Key Configuration ===".bright_cyan());

    // VirusTotal API key
    print!(
        "{}",
        "Enter VirusTotal API key (leave empty to skip): ".bright_white()
    );
    io::stdout().flush().unwrap();
    let mut vt_api_key = String::new();
    io::stdin()
        .read_line(&mut vt_api_key)
        .expect("Failed to read input");
    let vt_api_key = vt_api_key.trim();

    // Shodan API key
    print!(
        "{}",
        "Enter Shodan API key (leave empty to skip): ".bright_white()
    );
    io::stdout().flush().unwrap();
    let mut shodan_api_key = String::new();
    io::stdin()
        .read_line(&mut shodan_api_key)
        .expect("Failed to read input");
    let shodan_api_key = shodan_api_key.trim();

    // Confirm settings
    println!("\n{}", "=== Configuration Summary ===".bright_blue());
    if !vt_api_key.is_empty() {
        println!("VirusTotal API Key: {}", "[Set]".bright_green());
    }
    if !shodan_api_key.is_empty() {
        println!("Shodan API Key: {}", "[Set]".bright_green());
    }

    print!("\n{}", "Save configuration? (y/n): ".bright_white());
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin()
        .read_line(&mut confirm)
        .expect("Failed to read input");

    if confirm.trim().to_lowercase().starts_with('y') {
        println!("{}", "Saving configuration...".bright_green());

        // Save API keys
        if !vt_api_key.is_empty() {
            match config::set_api_key("virustotal", vt_api_key, verbose) {
                Ok(_) => println!("{}", "VirusTotal API key saved".bright_green()),
                Err(e) => eprintln!("{} {}", "Error saving VirusTotal API key:".bright_red(), e),
            }
        }

        if !shodan_api_key.is_empty() {
            match config::set_api_key("shodan", shodan_api_key, verbose) {
                Ok(_) => println!("{}", "Shodan API key saved".bright_green()),
                Err(e) => eprintln!("{} {}", "Error saving Shodan API key:".bright_red(), e),
            }
        }
    } else {
        println!("{}", "Configuration not saved.".bright_yellow());
    }
}

/// Interactive scan defaults configuration
async fn interactive_scan_defaults_config(verbose: bool) {
    use std::io::{self, Write};

    println!("\n{}", "=== Scan Defaults Configuration ===".bright_cyan());

    // Default scan type
    println!("\n{}", "Default Scan Type:".bright_yellow());
    println!("1. Basic");
    println!("2. Network");
    println!("3. Web");
    println!("4. Vulnerability");
    println!("5. SSL/TLS");
    println!("6. Full (comprehensive scan)");

    print!("\n{}", "Choose default scan type [1-6]: ".bright_white());
    io::stdout().flush().unwrap();
    let mut scan_type_choice = String::new();
    io::stdin()
        .read_line(&mut scan_type_choice)
        .expect("Failed to read input");

    let scan_type = match scan_type_choice.trim() {
        "1" => "Basic",
        "2" => "Network",
        "3" => "Web",
        "4" => "Vuln",
        "5" => "SSL",
        "6" => "Full",
        _ => {
            println!(
                "{}",
                "Invalid choice. Using Basic as default.".bright_yellow()
            );
            "Basic"
        }
    };

    // Default subdomain scanning
    print!(
        "{}",
        "Enable subdomain scanning by default? (y/n): ".bright_white()
    );
    io::stdout().flush().unwrap();
    let mut subdomain_choice = String::new();
    io::stdin()
        .read_line(&mut subdomain_choice)
        .expect("Failed to read input");
    let scan_subdomains = subdomain_choice.trim().to_lowercase().starts_with('y');

    // Confirm settings
    println!(
        "\n{}",
        "=== Default Configuration Summary ===".bright_blue()
    );
    println!("Default Scan Type: {}", scan_type.bright_white());
    println!(
        "Default Subdomain Scanning: {}",
        scan_subdomains.to_string().bright_white()
    );

    print!("\n{}", "Save configuration? (y/n): ".bright_white());
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin()
        .read_line(&mut confirm)
        .expect("Failed to read input");

    if confirm.trim().to_lowercase().starts_with('y') {
        println!("{}", "Saving configuration...".bright_green());

        match config::set_default_scan_type(scan_type, verbose) {
            Ok(_) => println!("{}", "Default scan type saved".bright_green()),
            Err(e) => eprintln!("{} {}", "Error saving default scan type:".bright_red(), e),
        }

        match config::set_default_subdomain_scanning(scan_subdomains, verbose) {
            Ok(_) => println!(
                "{}",
                "Default subdomain scanning setting saved".bright_green()
            ),
            Err(e) => eprintln!("{} {}", "Error saving subdomain setting:".bright_red(), e),
        }
    } else {
        println!("{}", "Configuration not saved.".bright_yellow());
    }
}
