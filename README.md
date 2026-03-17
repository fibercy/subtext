# Subtext

A steganographic chat system that hides encrypted messages within natural-looking cover text using LLM-based arithmetic coding.

## How It Works

Subtext uses **arithmetic coding over LLM logprobs** to embed hidden data in natural text:

1. **Encrypt**: The secret message is encrypted using X25519 ECDH key exchange + AES-256-GCM (compact 16-byte overhead variant).
2. **Encode**: The encrypted payload is split into segments. At each token position, the LLM returns top candidate tokens with log probabilities. Arithmetic coding selects a specific token based on the message bits, producing text that looks natural but carries hidden data.
3. **Send**: Only the cover text is sent over the network. The recipient has the shared key and the same LLM, so they can recover the bits.
4. **Decode**: The decoder regenerates the same LLM candidates at each position and uses arithmetic decoding to recover the hidden bits, then decrypts.

```
Secret: "Meet at 9" → Encrypt → Bits → Arithmetic Coding + LLM logprobs → "Nice weather today!"
                                                                                    ↓
                                                              Natural cover text (sent publicly)
```

## Features

- **End-to-end encryption**: X25519 ECDH key exchange + AES-256-GCM
- **Compact encryption**: Space-optimized variant (4-byte nonce + 4-byte truncated HMAC, 16 bytes total overhead) for fitting more content per cover sentence
- **Steganographic encoding**: Arithmetic coding over LLM logprobs — information-theoretically efficient and natural-looking
- **Quality filtering**: Multi-layer token filters reject non-English words, code artifacts, abbreviations, and emoticons — enforcing natural prose
- **LLM naturalness check**: Encoded segments are validated by the LLM itself for fluency before being accepted
- **Deniable encryption**: A single ciphertext decrypts to different plaintexts depending on which key is used — for plausible deniability under coercion
- **Interactive conversations**: Multi-segment encoding with peer reply context for natural back-and-forth flow
- **Local-first**: All cryptography runs on your device; only cover text leaves
- **gRPC API**: Easy integration with any language
- **CLI tool**: Full-featured command line interface

## Quick Start

### Prerequisites

- Go 1.24+
- [Ollama](https://ollama.ai/) with a supported model (must support `logprobs`)
- protoc (Protocol Buffers compiler)

### Setup Ollama

```bash
# Install Ollama (macOS)
brew install ollama

# Start Ollama server
ollama serve

# Pull the default model
ollama pull qwen2.5:14b
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
./bin/subtextd

# 2. Check status
./bin/subtext status

# 3. Create a session
./bin/subtext session create "alice@example.com" --name "Alice"

# 4. Perform key exchange
./bin/subtext session key-exchange <session-id>

# 5. Encode a secret message
./bin/subtext encode <session-id> "Meet at dock 7" --topic "fitness"

# 6. Decode a message
./bin/subtext decode <session-id> "<cover-text>" --topic "fitness"
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `subtext status` | Check daemon and Ollama status |
| `subtext session create <peer> --name <name>` | Create a new session |
| `subtext session list` | List all sessions |
| `subtext session key-exchange <id>` | Initiate key exchange |
| `subtext encode <id> <secret> --topic <topic>` | Encode secret into cover text |
| `subtext decode <id> <cover> --topic <topic>` | Decode secret from cover text |
| `subtext convo start <id> <secret> --topic <t>` | Start interactive multi-segment encoding |
| `subtext convo next <flow-id> <peer-reply>` | Continue encoding with next segment after peer reply |
| `subtext convo decode <id> --cover-file <f>` | Decode all collected segments |
| `subtext reply <message> --topic <topic>` | Generate a natural peer reply (no hidden data) |
| `subtext analyze <text>` | Analyze text for steganographic detection risk |

## Configuration

### Daemon Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `50051` | gRPC server port |
| `--data-dir` | `~/.subtext` | Data directory |
| `--ollama-url` | `http://localhost:11434` | Ollama API URL |
| `--model` | `qwen2.5:14b` | LLM model to use |

> Models must support the `logprobs` API parameter (e.g. Qwen, Llama 3). The daemon warms up the model on startup to stabilize logprob output.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Your Device                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ subtext CLI │◄──►│   Subtext   │◄──►│   Ollama    │  │
│  │             │gRPC│  (subtextd) │HTTP│(qwen2.5:14b)│  │
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
                    │  (any channel)  │
                    └─────────────────┘
```

## Encoding Details

### Arithmetic Coding over LLM Logprobs

At each token position, the LLM returns the top-20 candidate tokens with log probabilities. The arithmetic encoder maps these probabilities to intervals and selects the token whose interval contains the current message bits, advancing through the bitstream. The decoder runs the same forward pass to regenerate candidates and reverses the selection to recover bits.

Key design choices:
- **32-bit precision** with 15-bit quantized weights
- **Coarse 2.0-unit logprob buckets** for resilience against minor logprob variation between encode and decode runs
- **Alternating 1/0 padding** appended to each segment to prevent the AC value register from stalling
- **EOS recovery**: when the model emits end-of-sequence, generation resumes with a rotating continuation marker
- **Tail generation**: after all bits are encoded, the LLM completes the sentence naturally for cover quality
- **11 prompt variations** for retry — different prompts shift logprob distributions, enabling recovery when a segment fails quality checks (up to 12 attempts per segment)

### Quality Filters

Each candidate token is checked against multiple rejection rules:

- Non-English words (French, Spanish, German, Italian, Portuguese, Indonesian, etc.)
- Code artifacts: CamelCase/PascalCase identifiers, JSON/HTML/URL fragments, backslash, dollar sign
- Texting abbreviations: `lol`, `omg`, `tbh`, `imo`, etc.
- Invisible Unicode, non-ASCII characters, emoji
- Consonant-only sequences (`tty`, `nx`, etc.)
- Unnatural punctuation patterns and emoticons
- Word count outside the 5–150 word range per segment

Segments that pass token-level filtering are also submitted to the LLM for a **naturalness check** — the model scores whether the text reads as authentic human conversation.

### Deniable Encryption

The deniable layer stores both a real ciphertext and a decoy ciphertext in the same envelope, padded to identical length. The recipient uses the real shared key to recover the actual message; if coerced, a different decoy key decrypts to an innocent cover message. Max payload: 64 bytes per message.

## Directory Structure

```
.
├── cmd/
│   ├── subtext/          # CLI tool (Cobra)
│   │   └── cmd/          # Subcommands: encode, decode, session, convo, reply, analyze, whatsapp
│   └── subtextd/         # Daemon entry point
├── internal/
│   ├── analysis/         # Text statistics for steganographic detection analysis
│   ├── crypto/           # X25519 ECDH + AES-256-GCM (standard and compact variants)
│   ├── deniable/         # Deniable encryption (real + decoy ciphertext in one envelope)
│   ├── llm/              # Ollama HTTP client (logprobs, chat templates, model warmup)
│   ├── server/           # gRPC service implementation
│   ├── subtext/          # Steganographic encoder/decoder (arithmetic coding)
│   ├── store/            # SQLite storage (sessions, keys, messages)
│   └── whatsapp/         # WhatsApp bridge (in progress)
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
| Phase 5: WhatsApp Integration | 🔧 In Progress |
| Phase 6: Hardening | 🔲 Pending |

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-cover
```

## License

GPL-3.0 — see [LICENSE](LICENSE)
