<img src="https://github.com/user-attachments/assets/0edb0f04-5ca4-4c5e-a1ac-3dee617e8b73" width="200" alt="Docker Light Logo">

# docker-scan-lite

A lightweight Docker security scanner that analyzes Dockerfiles for vulnerabilities, secrets, insecure commands, and misconfigurations. No Docker daemon required — just static analysis on your Dockerfile.

**[Documentation & Landing Page](https://nickciolpan.github.io/docker-scan-lite)**

## Features

- **Base Image Analysis** — Detects 38+ known outdated image:tag combinations
- **Secret Detection** — AWS keys, GitHub tokens, JWTs, private keys, database URLs
- **Port Security** — Flags 20+ commonly vulnerable ports
- **Sensitive Env Vars** — 30+ patterns including cloud credentials
- **Insecure Commands** — curl -k, chmod 777, sudo su, and more
- **Package Pinning** — Unpinned apt, apk, yum, pip, npm, gem installs
- **Multi-stage Aware** — Tracks build stages and associates findings per stage
- **HEALTHCHECK Detection** — Warns when no HEALTHCHECK is present
- **USER Detection** — Warns when container runs as root by default
- **SHELL Analysis** — Flags non-standard shell configurations
- **Multiple Outputs** — Text, JSON, and SARIF formats
- **CI/CD Ready** — Exit codes, GitHub Action, severity filtering

## Installation

### Homebrew (macOS & Linux)

```bash
brew install nickciolpan/tap/docker-scan-lite
```

### Go Install

```bash
go install github.com/nickciolpan/docker-scan-lite@latest
```

### Linux (one-liner)

```bash
curl -sSL https://raw.githubusercontent.com/nickciolpan/docker-scan-lite/main/scripts/install.sh | bash
```

### Build from Source

```bash
git clone https://github.com/nickciolpan/docker-scan-lite
cd docker-scan-lite
make build
```

### Manual Download

Download pre-built binaries from [releases](https://github.com/nickciolpan/docker-scan-lite/releases) for Linux (amd64/arm64), macOS (Intel/Apple Silicon), and Windows.

## Usage

```bash
# Scan default Dockerfile
docker-scan-lite

# Scan a specific file
docker-scan-lite -f path/to/Dockerfile

# JSON output
docker-scan-lite -f Dockerfile -j

# SARIF output (for GitHub Code Scanning)
docker-scan-lite -f Dockerfile --sarif

# Filter by minimum severity
docker-scan-lite -f Dockerfile --severity medium

# Exit with code 1 if high-severity issues found (for CI)
docker-scan-lite -f Dockerfile --exit-code high
```

### CLI Options

```
Flags:
  -f, --file string       Path to Dockerfile (default "Dockerfile")
  -h, --help              Help for docker-scan-lite
  -j, --json              Output results in JSON format
      --sarif             Output results in SARIF format
  -v, --verbose           Verbose output
      --severity string   Minimum severity to report (info, low, medium, high)
      --exit-code string  Return exit code 1 if issues at or above this severity (info, low, medium, high)
      --version           Version for docker-scan-lite
```

## GitHub Action

Use docker-scan-lite directly in your GitHub Actions workflows:

```yaml
name: Dockerfile Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Scan Dockerfile
      uses: nickciolpan/docker-scan-lite@v1
      with:
        dockerfile: Dockerfile
        fail-on: high
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `dockerfile` | Path to Dockerfile | `Dockerfile` |
| `severity` | Minimum severity to report | `""` (all) |
| `fail-on` | Fail if issues at/above this severity | `high` |
| `format` | Output format: text, json, sarif | `text` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `total-issues` | Total number of issues found |
| `high-issues` | Number of high severity issues |
| `medium-issues` | Number of medium severity issues |
| `low-issues` | Number of low severity issues |

### SARIF Upload Example

```yaml
- name: Scan with SARIF
  uses: nickciolpan/docker-scan-lite@v1
  id: scan
  with:
    dockerfile: Dockerfile
    format: sarif
    fail-on: ''

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: scan-results.sarif
```

## Example Output

```
Docker Scan Lite Results

Dockerfile: examples/Dockerfile.sample
Scanned at: 2026-03-24 10:30:45

Summary
Total Issues: 18
  High: 5
  Medium: 11
  Low: 1
  Info: 1

Base Images
  ⚠️ ubuntu:16.04 (line 2) - Base image may be outdated or have known vulnerabilities

Environment Variables
  ⚠️ DATABASE_PASSWORD=mysecretpassword123 (line 5)
  ⚠️ API_KEY=sk-abcdef1234567890 (line 6)
  ⚠️ SECRET_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456 (line 7)

Potential Secrets
  ⚠️ generic_password: PASSWORD=mysecretpassword123 (line 5)
  ⚠️ private_key: -----BEGIN RSA PRIVATE KEY----- (line 28)

Security Issues
  ⚠️ [HIGH] Sensitive environment variable 'DATABASE_PASSWORD' found (line 5)
  ⚠️ [HIGH] Container running as root user (line 17)
  ⚠️ [MEDIUM] Port 22 may be vulnerable or should not be exposed (line 20)
  ⚠️ [MEDIUM] Potentially insecure command detected (line 13)
  ⚠️ [LOW] Package installation without version pinning detected (line 10)
  ⚠️ [INFO] No HEALTHCHECK instruction found

Review the issues above and consider fixing them to improve security.
```

## Security Checks

| Category | Severity | Examples |
|----------|----------|---------|
| Hardcoded secrets | High | AWS keys, GitHub tokens, JWTs, private keys, database URLs |
| Root user | High | `USER root`, `USER 0`, missing USER instruction |
| Sensitive env vars | High | PASSWORD, SECRET, API_KEY, TOKEN, AWS credentials |
| Outdated base images | Medium | ubuntu:16.04, node:8, python:2.7, alpine:3.5 |
| Vulnerable ports | Medium | 22 (SSH), 3306 (MySQL), 5432 (Postgres), 6379 (Redis) |
| Insecure commands | Medium | `curl -k`, `chmod 777`, `sudo su`, `wget --no-check-certificate` |
| ADD remote URLs | Medium | `ADD https://...` instead of COPY |
| Unpinned packages | Low | `apt-get install curl` without `=version` |
| Missing HEALTHCHECK | Info | No HEALTHCHECK instruction in Dockerfile |
| Latest tag | Low | Using implicit `:latest` tag |

## CI/CD Integration

### JSON Pipeline Gating

```bash
docker-scan-lite -j -f Dockerfile > report.json

if [ $(jq '.summary.high_severity' report.json) -gt 0 ]; then
  echo "High severity issues found!"
  exit 1
fi
```

### Exit Code Gating

```bash
# Fails with exit code 1 if any high severity issues exist
docker-scan-lite -f Dockerfile --exit-code high

# Fails on medium or above
docker-scan-lite -f Dockerfile --exit-code medium
```

## Development

```bash
make deps       # Download dependencies
make test       # Run unit tests with race detection
make coverage   # Run tests with coverage report
make build      # Build binary
make test-build # Integration test with example Dockerfiles
make vet        # Run go vet
make lint       # Run golangci-lint
make all        # Full pipeline: deps, fmt, vet, test, build, integration test
```

## Examples

Test with the provided sample Dockerfiles:

```bash
docker-scan-lite -f examples/Dockerfile.sample  # Many issues
docker-scan-lite -f examples/Dockerfile.clean    # Clean
docker-scan-lite -f examples/Dockerfile.webapp   # Mixed
```

## Supported Platforms

| Platform | Architecture | Format |
|----------|-------------|--------|
| Linux | amd64, arm64 | Binary, tar.gz |
| macOS | Intel, Apple Silicon | Homebrew, binary, tar.gz |
| Windows | amd64 | Binary, zip |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Write tests (`make test`)
5. Submit a pull request

## License

MIT License — see [LICENSE](LICENSE) file for details.

## Security Notice

This tool performs static analysis on Dockerfiles and may not catch all security issues. Always follow Docker security best practices and consider using additional tools for comprehensive analysis.

---

**Author**: [Nick Ciolpan](https://github.com/nickciolpan) (nick@ciolpan.com)

Follow [Graffino](https://graffino.com) for product design and software development.
