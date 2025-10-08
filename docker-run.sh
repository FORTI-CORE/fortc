#!/bin/bash

# FortiCore Docker Helper Script
# This script provides convenient commands to run FortiCore in Docker

set -e

IMAGE_NAME="forticore:latest"
CONTAINER_NAME="forticore-run"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Build the Docker image
build() {
    print_info "Building FortiCore Docker image..."
    docker build -t $IMAGE_NAME .
    print_info "Build complete!"
}

# Run a scan
scan() {
    if [ -z "$1" ]; then
        print_error "Please provide a target. Usage: ./docker-run.sh scan <target> [options]"
        exit 1
    fi
    
    print_info "Running scan on target: $1"
    
    # Create scans directory if it doesn't exist
    mkdir -p ./scans
    
    docker run --rm \
        --network host \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        -v "$(pwd)/scans:/home/fortc/scans" \
        --name $CONTAINER_NAME \
        $IMAGE_NAME scan "$@"
}

# Run exploitation
exploit() {
    if [ -z "$1" ]; then
        print_error "Please provide a target. Usage: ./docker-run.sh exploit <target> [options]"
        exit 1
    fi
    
    print_info "Running exploitation on target: $1"
    
    mkdir -p ./scans
    
    docker run --rm \
        --network host \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        -v "$(pwd)/scans:/home/fortc/scans" \
        --name $CONTAINER_NAME \
        $IMAGE_NAME exploit "$@"
}

# Generate report
report() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        print_error "Usage: ./docker-run.sh report <input-file> <output-file>"
        exit 1
    fi
    
    print_info "Generating report..."
    
    mkdir -p ./scans ./reports
    
    docker run --rm \
        -v "$(pwd)/scans:/home/fortc/scans" \
        -v "$(pwd)/reports:/home/fortc/reports" \
        --name $CONTAINER_NAME \
        $IMAGE_NAME report -i "$1" -o "$2"
}

# Interactive shell
shell() {
    print_info "Starting interactive shell in FortiCore container..."
    
    docker run --rm -it \
        --network host \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        -v "$(pwd)/scans:/home/fortc/scans" \
        --entrypoint /bin/bash \
        --name $CONTAINER_NAME \
        $IMAGE_NAME
}

# Show help
help() {
    cat << EOF
FortiCore Docker Helper Script

Usage: ./docker-run.sh <command> [arguments]

Commands:
    build                   Build the FortiCore Docker image
    scan <target> [opts]    Run a scan on the specified target
    exploit <target> [opts] Run exploitation on the specified target
    report <in> <out>       Generate a report from scan results
    shell                   Start an interactive shell in the container
    help                    Show this help message

Examples:
    # Build the image
    ./docker-run.sh build

    # Run a web scan
    ./docker-run.sh scan -t example.com -s web -v

    # Run a network scan with output
    ./docker-run.sh scan -t 192.168.1.1 -s network -o scan-results.json

    # Exploit vulnerabilities
    ./docker-run.sh exploit -t example.com --safe-mode true

    # Generate a report
    ./docker-run.sh report scans/example_com_scan.json reports/report.pdf

    # Interactive shell
    ./docker-run.sh shell

Security Notice:
    FortiCore requires elevated network capabilities (NET_RAW, NET_ADMIN) for
    scanning operations. Only use in authorized testing environments.

EOF
}

# Main command dispatcher
case "$1" in
    build)
        build
        ;;
    scan)
        shift
        scan "$@"
        ;;
    exploit)
        shift
        exploit "$@"
        ;;
    report)
        shift
        report "$@"
        ;;
    shell)
        shell
        ;;
    help|--help|-h|"")
        help
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        help
        exit 1
        ;;
esac
