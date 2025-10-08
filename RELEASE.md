# Creating a Release

This guide explains how to create a new release with the Debian package.

## Steps to Create a Release

### 1. Build the Debian Package

In WSL (to avoid permission issues):

```bash
# Copy project to native Linux directory
cp -r /mnt/c/users/user/Desktop/FORTICORE/fortc ~/fortc-build
cd ~/fortc-build

# Build the package
cargo deb

# Copy the .deb file back
cp target/debian/forticore_*.deb /mnt/c/users/user/Desktop/FORTICORE/fortc/
```

### 2. Create a Git Tag

```bash
# Commit all changes first
git add .
git commit -m "Release v0.1.0"

# Create and push the tag
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin main
git push origin v0.1.0
```

### 3. Create GitHub Release

1. Go to https://github.com/FORTI-CORE/fortc/releases
2. Click **"Draft a new release"**
3. Choose the tag: `v0.1.0`
4. Release title: `FortiCore v0.1.0`
5. Description (example):

```markdown
## FortiCore v0.1.0 - Initial Release

### Features
- Network vulnerability scanning (port scanning, service detection)
- Web application scanning (XSS, SQL injection, CORS, JWT analysis)
- SSL/TLS configuration analysis
- DNS enumeration with zone transfer detection
- Automated exploitation capabilities
- PDF and TXT report generation
- Docker support for easy deployment

### Installation

#### Debian/Ubuntu
```bash
wget https://github.com/FORTI-CORE/fortc/releases/download/v0.1.0/forticore_0.1.0-1_amd64.deb
sudo dpkg -i forticore_0.1.0-1_amd64.deb
sudo apt-get install -f
```

#### Docker
```bash
docker pull ghcr.io/forti-core/fortc:latest
# Or build from source
docker build -t forticore:latest .
```

### What's Changed
* Initial release with core scanning and exploitation features
* Docker support added
* Comprehensive documentation

**Full Changelog**: https://github.com/FORTI-CORE/fortc/commits/v0.1.0
```

6. **Attach the binary**: Drag and drop `forticore_0.1.0-1_amd64.deb` to the release assets
7. Click **"Publish release"**

### 4. Verify the Release

After publishing, verify the download link works:

```bash
wget https://github.com/FORTI-CORE/fortc/releases/latest/download/forticore_0.1.0-1_amd64.deb
```

## Automated Release (Optional)

You can automate this process using GitHub Actions. Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          
      - name: Install cargo-deb
        run: cargo install cargo-deb
        
      - name: Build Debian package
        run: cargo deb
        
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: target/debian/*.deb
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

With this workflow, simply push a tag and the release will be created automatically!
