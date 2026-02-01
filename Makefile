.PHONY: all proto build test clean run

# Default target
all: proto build

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	@mkdir -p proto
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/stego.proto

# Build the daemon
build:
	@echo "Building stegod..."
	go build -o bin/stegod ./cmd/stegod

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
	./bin/stegod

# Install protoc plugins (one-time setup)
install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Tidy dependencies
tidy:
	go mod tidy
