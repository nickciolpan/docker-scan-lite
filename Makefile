# Makefile for docker-scan-lite

.PHONY: build test test-build install clean help deps lint fmt all

# Build the binary
build:
	@echo "Building docker-scan-lite..."
	@go build -o docker-scan-lite

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	@go test -race -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out
	@echo ""
	@echo "To view HTML coverage: go tool cover -html=coverage.out"

# Build and test
test-build: build
	@echo "Testing built binary..."
	@./docker-scan-lite -f examples/Dockerfile.sample > /dev/null
	@./docker-scan-lite -f examples/Dockerfile.clean > /dev/null
	@./docker-scan-lite -f examples/Dockerfile.webapp > /dev/null
	@./docker-scan-lite -f examples/Dockerfile.sample -j > /dev/null
	@./docker-scan-lite -f examples/Dockerfile.sample --sarif > /dev/null
	@./docker-scan-lite -f examples/Dockerfile.clean --exit-code high && echo "Clean exit: OK"
	@echo "All tests passed!"

# Install to system PATH
install: build
	@echo "Installing docker-scan-lite to /usr/local/bin..."
	@sudo cp docker-scan-lite /usr/local/bin/
	@sudo chmod +x /usr/local/bin/docker-scan-lite
	@echo "docker-scan-lite installed successfully!"

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	@rm -f docker-scan-lite coverage.out
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

# Run go vet
vet:
	@echo "Running vet..."
	@go vet ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build the binary"
	@echo "  test        - Run unit tests with race detection"
	@echo "  coverage    - Run tests with coverage report"
	@echo "  test-build  - Build and integration-test the binary"
	@echo "  install     - Install to system PATH"
	@echo "  clean       - Clean build artifacts"
	@echo "  deps        - Download dependencies"
	@echo "  lint        - Run golangci-lint"
	@echo "  fmt         - Format code"
	@echo "  vet         - Run go vet"
	@echo "  help        - Show this help"

# Default target
all: deps fmt vet test build test-build
