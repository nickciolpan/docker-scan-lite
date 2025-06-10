# Makefile for docker-scan-lite

.PHONY: build test install clean help

# Build the binary
build:
	@echo "Building docker-scan-lite..."
	@go build -o docker-scan-lite

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Build and test
test-build: build
	@echo "Testing built binary..."
	@./docker-scan-lite -f examples/Dockerfile.sample > /dev/null
	@./docker-scan-lite -f examples/Dockerfile.clean > /dev/null
	@echo "✅ All tests passed!"

# Install to system PATH
install: build
	@echo "Installing docker-scan-lite to /usr/local/bin..."
	@sudo cp docker-scan-lite /usr/local/bin/
	@sudo chmod +x /usr/local/bin/docker-scan-lite
	@echo "✅ docker-scan-lite installed successfully!"

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	@rm -f docker-scan-lite
	@go clean

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod tidy
	@go mod download

# Run linter
lint:
	@echo "Running linter..."
	@golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build the binary"
	@echo "  test        - Run tests"
	@echo "  test-build  - Build and test the binary"
	@echo "  install     - Install to system PATH"
	@echo "  clean       - Clean build artifacts"
	@echo "  deps        - Download dependencies"
	@echo "  lint        - Run linter"
	@echo "  fmt         - Format code"
	@echo "  help        - Show this help"

# Default target
all: deps fmt build test-build 