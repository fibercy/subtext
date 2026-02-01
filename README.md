# Stegochat

A steganographic chat system that hides encrypted messages within natural-looking cover text using LLM-based encoding.

## Features

- **End-to-end encryption**: X25519 key exchange + AES-256-GCM
- **Steganographic encoding**: Messages hidden in LLM-generated cover text *(Phase 2)*
- **Deniable encryption**: Multiple decryption keys for plausible deniability
- **Local-first**: All crypto happens on your device, plaintext never leaves
- **gRPC API**: Easy integration with any language

## Project Status

| Phase | Status |
|-------|--------|
| Phase 1: Core Infrastructure | ✅ Complete |
| Phase 2: LLM Integration | 🔲 Pending |
| Phase 3: Deniable Encryption | 🔲 Pending |
| Phase 4: Client Apps | 🔲 Pending |
| Phase 5: WhatsApp Integration | 🔲 Pending |
| Phase 6: Hardening | 🔲 Pending |

## Quick Start

### Prerequisites

- Go 1.24+
- protoc (Protocol Buffers compiler)

### Build

```bash
# Install protoc plugins (one-time)
make install-tools

# Generate protobuf code
make proto

# Build the daemon
make build
```

### Run

```bash
# Start the daemon (defaults to port 50051)
./bin/stegod

# With custom port and data directory
./bin/stegod -port 9000 -data-dir /path/to/data
```

### Test

```bash
make test
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Your Device                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Chat App   │◄──►│ Stego Daemon│◄──►│ Local LLM   │  │
│  │             │gRPC│   (stegod)  │    │  (Ollama)   │  │
│  └─────────────┘    └──────┬──────┘    └─────────────┘  │
│                            │                             │
│                      ┌─────▼─────┐                       │
│                      │  SQLite   │                       │
│                      │ (encrypted)│                       │
│                      └───────────┘                       │
└─────────────────────────────────────────────────────────┘
                             │
                     Cover text only
                             ▼
                    ┌─────────────────┐
                    │  Public Network │
                    │   (WhatsApp)    │
                    └─────────────────┘
```

## API Overview

### Session Management
- `CreateSession` - Create a new chat session with a peer
- `GetSession` - Get session details
- `ListSessions` - List all sessions

### Key Exchange
- `InitiateKeyExchange` - Get your public key to share with peer
- `CompleteKeyExchange` - Complete exchange with peer's public key

### Messaging
- `EncodeMessage` - Encode secret message into cover text
- `DecodeMessage` - Decode secret from cover text

### Deniability
- `AddDecoyKey` - Add a decoy decryption key

## Directory Structure

```
.
├── cmd/
│   └── stegod/           # Daemon entry point
├── internal/
│   ├── crypto/           # X25519 + AES-256-GCM
│   ├── server/           # gRPC server implementation
│   └── store/            # SQLite storage
├── proto/
│   └── stego.proto       # gRPC service definition
├── Makefile
└── README.md
```

## License

MIT
