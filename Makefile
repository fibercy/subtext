.PHONY: all proto build build-cli build-all test clean run

# Default target
all: proto build-all

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	@mkdir -p proto
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/stego.proto

# Build the daemon
build:
	@echo "Building subtextd..."
	go build -o bin/subtextd ./cmd/subtextd

# Build the CLI
build-cli:
	@echo "Building subtext CLI..."
	go build -o bin/subtext ./cmd/subtext

# Build all binaries
build-all: build build-cli

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-cover:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html

# Run the daemon
run: build
	./bin/subtextd

# Install protoc plugins (one-time setup)
install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Tidy dependencies
tidy:
	go mod tidy
