# Stegochat

A steganographic chat system that hides encrypted messages within natural-looking cover text using LLM-based encoding.

## Features

- **End-to-end encryption**: X25519 key exchange + AES-256-GCM
- **Steganographic encoding**: Messages hidden in LLM-generated cover text using logprobs-based token selection
- **Deniable encryption**: Multiple decryption keys for plausible deniability
- **Local-first**: All crypto happens on your device, plaintext never leaves
- **gRPC API**: Easy integration with any language
- **CLI tool**: Full-featured command line interface

## How It Works

Stegochat uses **LLM logprobs** to hide information in natural-looking text:

1. **Encoding**: For each chunk of bits to hide, the LLM generates multiple candidate tokens. The encoder selects a specific candidate based on the bit value, producing text that appears natural but encodes secret data.

2. **Decoding**: The decoder regenerates the same candidates and determines which one was chosen, recovering the hidden bits.

```
Secret: "Meet at 9" → Encrypt → Bits → LLM Selection → "Nice weather today!"
                                                              ↓
                                          Natural cover text (sent publicly)
```

## Quick Start

### Prerequisites

- Go 1.24+
- [Ollama](https://ollama.ai/) with a supported model
- protoc (Protocol Buffers compiler)

### Setup Ollama

```bash
# Install Ollama (macOS)
brew install ollama

# Start Ollama server
ollama serve

# Pull the default model
ollama pull qwen3:8b
```

### Build

```bash
# Install protoc plugins (one-time)
make install-tools

# Build everything
make build-all
```

### Run Demo

```bash
# Run the demo script (requires Ollama running)
bash scripts/demo.sh
```

### Manual Usage

```bash
# 1. Start the daemon
./bin/stegod

# 2. Check status
./bin/stego status

# 3. Create a session
./bin/stego session create "alice@example.com" --name "Alice"

# 4. Perform key exchange
./bin/stego session key-exchange <session-id>

# 5. Encode a secret message
./bin/stego encode <session-id> "Meet at dock 7" --topic "fitness"

# 6. Decode a message
./bin/stego decode <session-id> "<cover-text>" --topic "fitness"
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `stego status` | Check daemon and Ollama status |
| `stego session create <peer> --name <name>` | Create a new session |
| `stego session list` | List all sessions |
| `stego session key-exchange <id>` | Initiate key exchange |
| `stego encode <id> <secret> --topic <topic>` | Encode secret into cover text |
| `stego decode <id> <cover> --topic <topic>` | Decode secret from cover text |
| `stego analyze <text>` | Analyze text for steganographic detection |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STEGOD_PORT` | `50051` | gRPC server port |
| `STEGOD_DATA_DIR` | `~/.stegochat` | Data directory |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API URL |

### Supported Models

The default model is `qwen3:8b`. You can change it by modifying `internal/llm/client.go`:

```go
const DefaultModel = "qwen3:8b"
```

Models must support the `logprobs` API parameter.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Your Device                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  stego CLI  │◄──►│ Stego Daemon│◄──►│   Ollama    │  │
│  │             │gRPC│   (stegod)  │HTTP│ (qwen3:8b)  │  │
│  └─────────────┘    └──────┬──────┘    └─────────────┘  │
│                            │                            │
│                      ┌─────▼─────┐                      │
│                      │  SQLite   │                      │
│                      │ (sessions)│                      │
│                      └───────────┘                      │
└─────────────────────────────────────────────────────────┘
                             │
                     Cover text only
                             ▼
                    ┌─────────────────┐
                    │  Public Network │
                    │   (WhatsApp)    │
                    └─────────────────┘
```

## Directory Structure

```
.
├── cmd/
│   ├── stego/            # CLI tool
│   │   └── cmd/          # Cobra commands
│   └── stegod/           # Daemon entry point
├── internal/
│   ├── analysis/         # Text analysis for detection
│   ├── crypto/           # X25519 + AES-256-GCM
│   ├── deniable/         # Deniable encryption
│   ├── llm/              # Ollama client
│   ├── server/           # gRPC server
│   ├── stego/            # Steganographic encoding/decoding
│   └── store/            # SQLite storage
├── proto/
│   └── stego.proto       # gRPC service definition
├── scripts/
│   └── demo.sh           # Demo script
└── Makefile
```

## Project Status

| Phase | Status |
|-------|--------|
| Phase 1: Core Infrastructure | ✅ Complete |
| Phase 2: LLM Integration | ✅ Complete |
| Phase 3: Deniable Encryption | ✅ Complete |
| Phase 4: CLI Tool | ✅ Complete |
| Phase 5: WhatsApp Integration | 🔲 Pending |
| Phase 6: Hardening | 🔲 Pending |

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-cover
```

## License

MIT

