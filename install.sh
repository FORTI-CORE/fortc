#!/bin/bash

# FortiCore Installation Script
echo "=============================="
echo "FortiCore Installation"
echo "=============================="

# Check if we're running as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (use sudo)"
  exit 1
fi

# Check system
echo "Checking system requirements..."

# Check if cargo is available to the current user (root or otherwise)
if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust and Cargo are required but not installed."
  echo "Install Rust using: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "After installation, run: source \"$HOME/.cargo/env\" && bash install.sh"
  exit 1
fi

# Install dependencies
echo "Installing system dependencies..."
if [ -f /etc/debian_version ]; then
  # Debian/Ubuntu
  apt-get update
  apt-get install -y build-essential pkg-config libssl-dev
elif [ -f /etc/redhat-release ]; then
  # CentOS/RHEL/Fedora
  yum groupinstall -y "Development Tools"
  yum install -y openssl-devel
else
  echo "Unsupported OS. Please install dependencies manually."
  exit 1
fi

# Build FortiCore
echo "Building FortiCore..."
cd "$(dirname "$0")"
cargo build --release

# Check if build succeeded
if [ $? -ne 0 ]; then
  echo "Build failed. Please check the error messages above."
  exit 1
fi

# Install binary
echo "Installing FortiCore..."
cp target/release/fortc /usr/local/bin/
chmod +x /usr/local/bin/fortc

# Create completion script
echo "Setting up command completion..."
mkdir -p /etc/bash_completion.d
cat > /etc/bash_completion.d/fortc << 'EOF'
_fortc() {
    local cur prev words cword
    _init_completion || return

    case $prev in
        -t|--target)
            return
            ;;
        --scan-type)
            COMPREPLY=( $( compgen -W "basic network web full" -- "$cur" ) )
            return
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $( compgen -W "-t --target -s --scan-type -o --output -v --verbose -h --help" -- "$cur" ) )
    else
        COMPREPLY=( $( compgen -W "scan exploit report interactive" -- "$cur" ) )
    fi
} &&
complete -F _fortc fortc
EOF

# Create folders for FortiCore
echo "Creating configuration directories..."
mkdir -p /etc/forticore
mkdir -p /var/lib/forticore/reports
mkdir -p /var/lib/forticore/scans

# Set permissions
chmod -R 755 /etc/forticore
chmod -R 755 /var/lib/forticore

echo "=============================="
echo "FortiCore installed successfully!"
echo "Run 'fortc --help' to get started"
echo "==============================" 