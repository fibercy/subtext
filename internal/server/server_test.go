package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cy/subtext/internal/store"
	pb "github.com/cy/subtext/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

func setupTestServer(t *testing.T) (pb.StegoServiceClient, func()) {
	t.Helper()

	// Create temp directory for test db
	tmpDir, err := os.MkdirTemp("", "stego-server-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	st, err := store.New(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create in-memory listener
	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	stegoServer := New(st)
	pb.RegisterStegoServiceServer(grpcServer, stegoServer)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("Server exited: %v", err)
		}
	}()

	// Create client
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		grpcServer.Stop()
		st.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to dial: %v", err)
	}

	client := pb.NewStegoServiceClient(conn)

	cleanup := func() {
		conn.Close()
		grpcServer.Stop()
		st.Close()
		os.RemoveAll(tmpDir)
	}

	return client, cleanup
}

func TestCreateAndGetSession(t *testing.T) {
	client, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()

	// Create session
	createResp, err := client.CreateSession(ctx, &pb.CreateSessionRequest{
		PeerId:      "alice@example.com",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if createResp.Id == "" {
		t.Error("Session ID should not be empty")
	}
	if createResp.PeerId != "alice@example.com" {
		t.Errorf("PeerID mismatch: got %s", createResp.PeerId)
	}
	if createResp.State != pb.SessionState_SESSION_STATE_PENDING_KEY_EXCHANGE {
		t.Errorf("State should be pending key exchange: got %v", createResp.State)
	}

	// Get session
	getResp, err := client.GetSession(ctx, &pb.GetSessionRequest{
		SessionId: createResp.Id,
	})
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if getResp.Id != createResp.Id {
		t.Errorf("ID mismatch: got %s, want %s", getResp.Id, createResp.Id)
	}
}

func TestKeyExchange(t *testing.T) {
	client, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()

	// Create two sessions (simulating Alice and Bob)
	aliceSession, err := client.CreateSession(ctx, &pb.CreateSessionRequest{
		PeerId:      "bob@example.com",
		DisplayName: "Bob",
	})
	if err != nil {
		t.Fatalf("CreateSession (Alice) failed: %v", err)
	}

	bobSession, err := client.CreateSession(ctx, &pb.CreateSessionRequest{
		PeerId:      "alice@example.com",
		DisplayName: "Alice",
	})
	if err != nil {
		t.Fatalf("CreateSession (Bob) failed: %v", err)
	}

	// Initiate key exchange for Alice
	aliceKeyResp, err := client.InitiateKeyExchange(ctx, &pb.InitiateKeyExchangeRequest{
		SessionId: aliceSession.Id,
	})
	if err != nil {
		t.Fatalf("InitiateKeyExchange (Alice) failed: %v", err)
	}
	if len(aliceKeyResp.PublicKey) != 32 {
		t.Errorf("Alice public key wrong size: %d", len(aliceKeyResp.PublicKey))
	}

	// Initiate key exchange for Bob
	bobKeyResp, err := client.InitiateKeyExchange(ctx, &pb.InitiateKeyExchangeRequest{
		SessionId: bobSession.Id,
	})
	if err != nil {
		t.Fatalf("InitiateKeyExchange (Bob) failed: %v", err)
	}

	// Complete key exchange - Alice receives Bob's public key
	completeResp, err := client.CompleteKeyExchange(ctx, &pb.CompleteKeyExchangeRequest{
		SessionId:     aliceSession.Id,
		PeerPublicKey: bobKeyResp.PublicKey,
	})
	if err != nil {
		t.Fatalf("CompleteKeyExchange (Alice) failed: %v", err)
	}
	if !completeResp.Success {
		t.Error("CompleteKeyExchange should succeed")
	}

	// Verify session is now active
	session, err := client.GetSession(ctx, &pb.GetSessionRequest{
		SessionId: aliceSession.Id,
	})
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session.State != pb.SessionState_SESSION_STATE_ACTIVE {
		t.Errorf("Session should be active after key exchange: got %v", session.State)
	}
}

func TestListSessions(t *testing.T) {
	client, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()

	// Create multiple sessions
	for i := 0; i < 5; i++ {
		_, err := client.CreateSession(ctx, &pb.CreateSessionRequest{
			PeerId:      "peer-" + string(rune('A'+i)),
			DisplayName: "Peer " + string(rune('A'+i)),
		})
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
	}

	// List sessions
	listResp, err := client.ListSessions(ctx, &pb.ListSessionsRequest{
		Limit:  10,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}

	if listResp.Total != 5 {
		t.Errorf("Total should be 5: got %d", listResp.Total)
	}
	if len(listResp.Sessions) != 5 {
		t.Errorf("Should have 5 sessions: got %d", len(listResp.Sessions))
	}
}

func TestEncodeDecodeMessagePlaceholder(t *testing.T) {
	client, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()

	// Create and set up a session with key exchange
	session, _ := client.CreateSession(ctx, &pb.CreateSessionRequest{
		PeerId:      "bob",
		DisplayName: "Bob",
	})

	// Create "Bob's" session to get a public key to exchange
	bobSession, _ := client.CreateSession(ctx, &pb.CreateSessionRequest{
		PeerId:      "alice",
		DisplayName: "Alice",
	})
	bobKey, _ := client.InitiateKeyExchange(ctx, &pb.InitiateKeyExchangeRequest{
		SessionId: bobSession.Id,
	})

	// Complete key exchange
	client.CompleteKeyExchange(ctx, &pb.CompleteKeyExchangeRequest{
		SessionId:     session.Id,
		PeerPublicKey: bobKey.PublicKey,
	})

	// Try to encode a message (should return placeholder since LLM not implemented)
	encodeResp, err := client.EncodeMessage(ctx, &pb.EncodeMessageRequest{
		SessionId:     session.Id,
		SecretMessage: "Meet at 9pm",
		TopicHint:     "weekend plans",
	})
	if err != nil {
		t.Fatalf("EncodeMessage failed: %v", err)
	}

	// Verify we get a placeholder response
	if encodeResp.CoverText == "" {
		t.Error("CoverText should not be empty")
	}
	if encodeResp.BitsEncoded == 0 {
		t.Error("BitsEncoded should not be 0")
	}
	if encodeResp.MessageId == "" {
		t.Error("MessageId should not be empty")
	}

	t.Logf("Encode response: cover=%s, bits=%d", encodeResp.CoverText, encodeResp.BitsEncoded)
}

func TestAddDecoyKey(t *testing.T) {
	client, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()

	session, _ := client.CreateSession(ctx, &pb.CreateSessionRequest{
		PeerId:      "bob",
		DisplayName: "Bob",
	})

	// Add decoy key
	decoyResp, err := client.AddDecoyKey(ctx, &pb.AddDecoyKeyRequest{
		SessionId:    session.Id,
		DecoyMessage: "Nothing to see here!",
	})
	if err != nil {
		t.Fatalf("AddDecoyKey failed: %v", err)
	}

	if len(decoyResp.DecoyKey) != 32 {
		t.Errorf("DecoyKey wrong size: %d", len(decoyResp.DecoyKey))
	}
	if decoyResp.DecoyKeyId == "" {
		t.Error("DecoyKeyId should not be empty")
	}
}

func TestEncodeDeniableMessage(t *testing.T) {
	client, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()

	// Create and set up a session with key exchange
	session, _ := client.CreateSession(ctx, &pb.CreateSessionRequest{
		PeerId:      "bob",
		DisplayName: "Bob",
	})

	// Create "Bob's" session to get a public key to exchange
	bobSession, _ := client.CreateSession(ctx, &pb.CreateSessionRequest{
		PeerId:      "alice",
		DisplayName: "Alice",
	})
	bobKey, _ := client.InitiateKeyExchange(ctx, &pb.InitiateKeyExchangeRequest{
		SessionId: bobSession.Id,
	})

	// Complete key exchange
	client.CompleteKeyExchange(ctx, &pb.CompleteKeyExchangeRequest{
		SessionId:     session.Id,
		PeerPublicKey: bobKey.PublicKey,
	})

	// Encode a deniable message (with decoy)
	encodeResp, err := client.EncodeMessage(ctx, &pb.EncodeMessageRequest{
		SessionId:     session.Id,
		SecretMessage: "Meet at dock 7",
		DecoyMessage:  "Coffee tomorrow?",
		TopicHint:     "weekend plans",
	})
	if err != nil {
		t.Fatalf("EncodeMessage with decoy failed: %v", err)
	}

	// Should get a response (placeholder since no LLM)
	if encodeResp.CoverText == "" {
		t.Error("CoverText should not be empty")
	}
	if encodeResp.MessageId == "" {
		t.Error("MessageId should not be empty")
	}

	// Bits should be larger since deniable encryption has overhead
	t.Logf("Deniable encode response: cover=%s, bits=%d", encodeResp.CoverText, encodeResp.BitsEncoded)
}
