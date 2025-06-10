#!/bin/bash
set -e

REPO="nickciolpan/docker-scan-lite"
VERSION=${1:-latest}

get_latest_release() {
    curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
}

detect_os_arch() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        arm64) ARCH="arm64" ;;
        aarch64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    case $OS in
        linux) OS="linux" ;;
        darwin) OS="darwin" ;;
        *) echo "Unsupported OS: $OS"; exit 1 ;;
    esac
}

main() {
    if [ "$VERSION" = "latest" ]; then
        VERSION=$(get_latest_release)
    fi
    
    detect_os_arch
    
    BINARY_NAME="docker-scan-lite-${OS}-${ARCH}"
    if [ "$OS" = "windows" ]; then
        BINARY_NAME="${BINARY_NAME}.exe"
    fi
    
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/${BINARY_NAME}"
    
    echo "Downloading docker-scan-lite $VERSION for $OS/$ARCH..."
    
    if command -v curl >/dev/null 2>&1; then
        curl -L "$DOWNLOAD_URL" -o docker-scan-lite
    elif command -v wget >/dev/null 2>&1; then
        wget "$DOWNLOAD_URL" -O docker-scan-lite
    else
        echo "Error: curl or wget is required"
        exit 1
    fi
    
    chmod +x docker-scan-lite
    
    if [ -w "/usr/local/bin" ]; then
        mv docker-scan-lite /usr/local/bin/
        echo "✅ docker-scan-lite installed to /usr/local/bin/"
    else
        echo "Moving docker-scan-lite to /usr/local/bin/ (requires sudo)..."
        sudo mv docker-scan-lite /usr/local/bin/
        echo "✅ docker-scan-lite installed to /usr/local/bin/"
    fi
    
    echo "Run 'docker-scan-lite --help' to get started!"
}

main "$@" 