# Release Process

This document outlines the steps to create a new release of docker-scan-lite.

## Prerequisites

1. All changes committed to `main` branch
2. Tests passing locally: `make test-build`
3. Version updated in `main.go` if needed

## Release Steps

### 1. Create and Push Tag

```bash
# Ensure you're on main and up to date
git checkout main
git pull origin main

# Create a new tag (replace x.y.z with actual version)
git tag v1.0.0
git push origin v1.0.0
```

### 2. Automated Build

The GitHub Actions workflow will automatically:
- Build binaries for all platforms (Linux, macOS, Windows)
- Create release archives (.tar.gz and .zip)
- Create a GitHub release with all artifacts
- Generate release notes

### 3. Update Homebrew Formula

After the release is created, update the Homebrew formula with correct SHA256 hashes:

```bash
# Run the update script
./scripts/update-formula.sh 1.0.0

# Review the changes
git diff Formula/docker-scan-lite.rb

# Commit the updated formula
git add Formula/docker-scan-lite.rb
git commit -m "Update Homebrew formula for v1.0.0"
git push origin main
```

### 4. Test Installation

Test the installation methods:

```bash
# Test Homebrew (if you have a tap set up)
brew install nickciolpan/tap/docker-scan-lite

# Test install script
curl -sSL https://raw.githubusercontent.com/nickciolpan/docker-scan-lite/main/scripts/install.sh | bash

# Test Go install
go install github.com/nickciolpan/docker-scan-lite@latest
```

### 5. Announcement

After successful release:
1. Update README.md if needed
2. Post on social media
3. Share in relevant communities
4. Update any documentation sites

## Release Artifacts

Each release includes:

- **Linux AMD64**: `docker-scan-lite-linux-amd64.tar.gz`
- **Linux ARM64**: `docker-scan-lite-linux-arm64.tar.gz`
- **macOS AMD64**: `docker-scan-lite-darwin-amd64.tar.gz`
- **macOS ARM64**: `docker-scan-lite-darwin-arm64.tar.gz`
- **Windows AMD64**: `docker-scan-lite-windows-amd64.exe.zip`

## Versioning

We follow semantic versioning (semver):
- **MAJOR**: Breaking changes
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

## Rollback

If a release has issues:

1. Delete the problematic tag:
   ```bash
   git tag -d v1.0.0
   git push origin :refs/tags/v1.0.0
   ```

2. Delete the GitHub release through the web interface

3. Fix issues and create a new release

## Post-Release Checklist

- [ ] Release created successfully
- [ ] All binaries download and work
- [ ] Homebrew formula updated
- [ ] Installation scripts tested
- [ ] Documentation updated
- [ ] Social media announcement posted 