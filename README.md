# docker-scan-lite 🐳

A lightweight Docker image scanner that analyzes Dockerfiles for security issues, outdated base images, exposed ports, environment variables, and potential secrets. No Docker daemon integration required - just parses your Dockerfile!

## Features

- **🏗️ Base Image Analysis**: Detects outdated or vulnerable base images
- **🔌 Port Security**: Identifies potentially vulnerable exposed ports
- **🌍 Environment Variables**: Flags sensitive environment variables
- **🔐 Secret Detection**: Finds potential secrets, API keys, and credentials
- **🔒 Security Issues**: Identifies insecure commands and configurations
- **📊 Summary Report**: Clear overview of all security findings
- **🎨 Formatted Output**: Beautiful, colored terminal output
- **📄 JSON Export**: Machine-readable JSON output for CI/CD integration

## Installation

### Homebrew (macOS)

```bash
# Add the tap (once published)
brew tap nickciolpan/tap

# Install docker-scan-lite
brew install docker-scan-lite
```

### Linux (One-liner install)

```bash
# Install latest version
curl -sSL https://raw.githubusercontent.com/nickciolpan/docker-scan-lite/main/scripts/install.sh | bash

# Install specific version
curl -sSL https://raw.githubusercontent.com/nickciolpan/docker-scan-lite/main/scripts/install.sh | bash -s v1.0.0
```

### Manual Installation

1. Download the appropriate binary from [releases](https://github.com/nickciolpan/docker-scan-lite/releases)
2. Extract and place in your PATH:

```bash
# Linux/macOS
tar -xzf docker-scan-lite-*.tar.gz
sudo mv docker-scan-lite-* /usr/local/bin/docker-scan-lite
chmod +x /usr/local/bin/docker-scan-lite
```

### Build from Source

```bash
git clone https://github.com/nickciolpan/docker-scan-lite
cd docker-scan-lite
make build
```

### Using Go Install

```bash
go install github.com/nickciolpan/docker-scan-lite@latest
```

## Usage

### Basic Usage

```bash
# Scan a Dockerfile in the current directory
docker-scan-lite

# Scan a specific Dockerfile
docker-scan-lite -f path/to/Dockerfile

# Output results in JSON format
docker-scan-lite -j

# Verbose output
docker-scan-lite -v
```

### CLI Options

```
Flags:
  -f, --file string    Path to Dockerfile (default "Dockerfile")
  -h, --help          Help for docker-scan-lite
  -j, --json          Output results in JSON format
  -v, --verbose       Verbose output
```

## Example Output

```
🐳 Docker Scan Lite Results

Dockerfile: examples/Dockerfile.sample
Scanned at: 2024-01-15 10:30:45

📊 Summary
Total Issues: 12
  High: 4
  Medium: 6
  Low: 2

🏗️ Base Images
  ⚠️ ubuntu:16.04 (line 2) - Base image may be outdated or have known vulnerabilities

🔌 Exposed Ports
  22
  3306
  6379

🌍 Environment Variables
  ⚠️ DATABASE_PASSWORD=mysecretpassword123 (line 5)
  ⚠️ API_KEY=sk-abcdef1234567890 (line 6)
  ⚠️ SECRET_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456 (line 7)

🔐 Potential Secrets
  ⚠️ generic_password: mysecretpassword123 (line 5)
  ⚠️ github_token: ghp_abcdefghijklmnopqrstuvwxyz123456 (line 7)
  ⚠️ private_key: -----BEGIN RSA PRIVATE KEY----- (line 27)
  ⚠️ jwt_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 (line 28)

🔒 Security Issues
  ⚠️ [HIGH] Sensitive environment variable 'DATABASE_PASSWORD' found (line 5)
  ⚠️ [HIGH] Sensitive environment variable 'API_KEY' found (line 6)
  ⚠️ [HIGH] Sensitive environment variable 'SECRET_TOKEN' found (line 7)
  ⚠️ [HIGH] Container running as root user (line 19)
  ⚠️ [MEDIUM] Port 22 may be vulnerable or should not be exposed (line 22)
  ⚠️ [MEDIUM] Port 3306 may be vulnerable or should not be exposed (line 23)
  ⚠️ [MEDIUM] Port 6379 may be vulnerable or should not be exposed (line 24)
  ⚠️ [MEDIUM] Potentially insecure command detected (line 16)
  ⚠️ [MEDIUM] ADD instruction with remote URL detected, consider using COPY instead (line 26)
  ⚠️ [LOW] Package installation without version pinning detected (line 10)

Review the issues above and consider fixing them to improve security.
```

## Security Checks

### Base Images
- Detects known outdated base images
- Warns about using `latest` tag in production
- Checks against a curated list of vulnerable images

### Vulnerable Ports
- SSH (22), Telnet (23), SMTP (25)
- Database ports (3306, 5432, 27017, etc.)
- Remote desktop (3389)
- And many more...

### Sensitive Environment Variables
- Passwords, secrets, API keys, tokens
- Database credentials
- Cloud provider keys (AWS, etc.)
- JWT secrets

### Secret Detection
- AWS access keys and secret keys
- GitHub tokens
- JWT tokens
- Private keys
- Database URLs
- Generic API keys and passwords

### Insecure Commands
- `curl -k` (insecure SSL)
- `wget --no-check-certificate`
- `chmod 777` (overly permissive)
- `su root`, `sudo su`
- SSH without host key checking

### Package Management
- Unpinned package versions
- Missing version constraints
- Supports apt, yum, pip, npm, gem, apk

## CI/CD Integration

Use the JSON output for automated security scanning:

```bash
# Generate JSON report
docker-scan-lite -j -f Dockerfile > security-report.json

# Parse results in your CI pipeline
if [ $(jq '.summary.high_severity' security-report.json) -gt 0 ]; then
  echo "High severity security issues found!"
  exit 1
fi
```

## Configuration

The tool comes with sensible defaults, but you can extend the security rules by modifying the `internal/rules/rules.go` file to add:

- Custom secret patterns
- Additional vulnerable ports
- More sensitive environment variable names
- Extra insecure command patterns

## Examples

Test the scanner with the provided sample:

```bash
# Scan the sample Dockerfile with security issues
docker-scan-lite -f examples/Dockerfile.sample
```

## Distribution

### For Linux Distributions

We provide pre-built binaries for:
- Linux AMD64
- Linux ARM64

Available formats:
- Direct binary downloads
- Installation script
- Package manager integration (coming soon)

### For macOS

Available through:
- Homebrew tap
- Direct binary downloads
- Build from source

### For Windows

Available as:
- Windows executable (.exe)
- Build from source

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Write tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security Notice

This tool analyzes Dockerfiles statically and may not catch all security issues. Always follow Docker security best practices and consider using additional security tools for comprehensive analysis.

---

**Author**: Nick Ciolpan (nick@ciolpan.com)

Follow [Graffino](https://graffino.com) and [Short.Inc](https://short.inc) for product design and software development.

Built with ❤️ in Go 