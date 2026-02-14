// Command stegod is the steganographic chat daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cy/stegochat/internal/llm"
	"github.com/cy/stegochat/internal/server"
	"github.com/cy/stegochat/internal/store"
	pb "github.com/cy/stegochat/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	port      = flag.Int("port", 50051, "The server port")
	dataDir   = flag.String("data-dir", "", "Data directory (default: ~/.stegochat)")
	ollamaURL = flag.String("ollama-url", "http://localhost:11434", "Ollama API URL")
	model     = flag.String("model", "qwen2.5:14b", "LLM model to use")
)

func main() {
	flag.Parse()

	// Determine data directory
	dir := *dataDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to get home directory: %v", err)
		}
		dir = filepath.Join(home, ".stegochat")
	}

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize store
	dbPath := filepath.Join(dir, "stegochat.db")
	st, err := store.New(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer st.Close()

	log.Printf("Using database: %s", dbPath)

	// Initialize LLM client
	llmClient := llm.NewClient(
		llm.WithBaseURL(*ollamaURL),
		llm.WithModel(*model),
	)

	// Check if Ollama is available
	var serverOpts []server.ServerOption
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := llmClient.Ping(ctx); err != nil {
		log.Printf("WARNING: Ollama not available at %s: %v", *ollamaURL, err)
		log.Printf("Steganographic encoding/decoding will be disabled.")
		log.Printf("To enable, start Ollama with: ollama run %s", *model)
	} else {
		log.Printf("Connected to Ollama at %s (model: %s)", *ollamaURL, *model)
		if tmpl, err := llmClient.FetchChatTemplate(ctx); err != nil {
			log.Printf("WARNING: could not fetch chat template: %v", err)
		} else if tmpl != nil {
			log.Printf("Using chat template (system: %q)", tmpl.SystemMessage[:min(40, len(tmpl.SystemMessage))])
		}
		// Warm up model to stabilize logprobs (first call after load differs)
		warmCtx, warmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = llmClient.Generate(warmCtx, "hello", llm.GenerateOptions{NumPredict: 1}, false)
		warmCancel()
		log.Printf("Model warm-up complete")
		serverOpts = append(serverOpts, server.WithLLMClient(llmClient))
	}

	// Create gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	stegoServer := server.New(st, serverOpts...)
	pb.RegisterStegoServiceServer(grpcServer, stegoServer)

	// Enable reflection for development (allows grpcurl, etc.)
	reflection.Register(grpcServer)

	// Handle graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-done
		log.Println("Shutting down server...")
		grpcServer.GracefulStop()
	}()

	log.Printf("Stego daemon listening on port %d", *port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
