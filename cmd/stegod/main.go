// Command stegod is the steganographic chat daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cy/stegochat/internal/server"
	"github.com/cy/stegochat/internal/store"
	pb "github.com/cy/stegochat/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	port    = flag.Int("port", 50051, "The server port")
	dataDir = flag.String("data-dir", "", "Data directory (default: ~/.stegochat)")
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

	// Create gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	stegoServer := server.New(st)
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
