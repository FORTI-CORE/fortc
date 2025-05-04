# FortiCore Resources

This directory contains resource files used by FortiCore for various scanning and exploitation tasks.

## Resource Files

- **subdomains.json**: Contains lists of common subdomains used for subdomain enumeration
- **payloads.json**: Contains various security testing payloads (XSS, SQL injection, etc.)
- (You can add more resource files as needed)

## Usage

The resources are loaded automatically at runtime. In your code, you can access them using the `resources` module:

```rust
use crate::resources;

// Load subdomains
let subdomains = resources::load_subdomains()?;

// Load XSS payloads
let xss_payloads = resources::load_xss_payloads()?;

// Load SQL injection payloads
let sql_payloads = resources::load_sql_injection_payloads()?;

// Load directory traversal payloads
let traversal_payloads = resources::load_directory_traversal_payloads()?;

// Load LFI payloads
let lfi_payloads = resources::load_lfi_payloads()?;

// Load open redirect payloads
let redirect_payloads = resources::load_open_redirect_payloads()?;

// Load security headers
let security_headers = resources::load_security_headers()?;
```

## Adding New Resources

To add a new resource type:

1. Create a new JSON file in this directory with the appropriate structure
2. Update the `mod.rs` file to add loading functions for your new resource
3. Add the new file to the `ensure_resources_exist` function in `mod.rs`

## Updating Resources

You can update resources by:

1. Editing the JSON files directly
2. Using the Python script in `scripts/update_resources.py`

### Using the Update Script

The `update_resources.py` script provides easy ways to update resources:

```bash
# Add a new subdomain to the list
python scripts/update_resources.py add subdomains.json common_subdomains new-subdomain.example.com

# Remove a subdomain
python scripts/update_resources.py remove subdomains.json common_subdomains old-subdomain.example.com

# List all subdomains
python scripts/update_resources.py list subdomains.json --key common_subdomains

# Add multiple items from a file (one per line)
python scripts/update_resources.py bulk payloads.json xss_payloads new_xss_payloads.txt

# Create a new resource file
python scripts/update_resources.py create custom_paths.json common_paths

# List all available resource files
python scripts/update_resources.py files
```

## Benefits of the Resource System

- **Separation of Code and Data**: Payload data is stored separately from business logic
- **Easy Updates**: Resources can be updated without changing code
- **Caching**: Resources are cached in memory for better performance
- **Modularity**: New resources can be added easily without modifying existing code
- **Maintainability**: Easier to maintain and update lists of payloads, subdomains, etc.
