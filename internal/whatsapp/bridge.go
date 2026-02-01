// Package whatsapp provides WhatsApp integration using whatsmeow.
package whatsapp

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mdp/qrterminal/v3"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	pb "github.com/cy/stegochat/proto"
	"google.golang.org/protobuf/proto"
)

// Bridge handles WhatsApp <-> Stego integration
type Bridge struct {
	client      *whatsmeow.Client
	stegoClient pb.StegoServiceClient
	container   *sqlstore.Container
	device      *store.Device

	// Maps WhatsApp JID to session ID
	sessionMap map[string]string

	// Message handler
	onMessage func(from string, message string, isDecoded bool)
}

// BridgeConfig configures the bridge
type BridgeConfig struct {
	DBPath      string // Path to whatsmeow SQLite database
	StegoClient pb.StegoServiceClient
	OnMessage   func(from string, message string, isDecoded bool)
}

// NewBridge creates a new WhatsApp bridge
func NewBridge(ctx context.Context, cfg BridgeConfig) (*Bridge, error) {
	// Initialize whatsmeow store
	container, err := sqlstore.New(ctx, "sqlite3", fmt.Sprintf("file:%s?_foreign_keys=on", cfg.DBPath), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	// Get or create device
	deviceStore, err := container.GetFirstDevice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	client := whatsmeow.NewClient(deviceStore, nil)

	return &Bridge{
		client:      client,
		stegoClient: cfg.StegoClient,
		container:   container,
		device:      deviceStore,
		sessionMap:  make(map[string]string),
		onMessage:   cfg.OnMessage,
	}, nil
}

// Connect connects to WhatsApp, showing QR code if needed
func (b *Bridge) Connect(ctx context.Context) error {
	// Register event handler
	b.client.AddEventHandler(b.handleEvent)

	if b.client.Store.ID == nil {
		// Not logged in, need QR code
		qrChan, _ := b.client.GetQRChannel(ctx)
		err := b.client.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}

		for evt := range qrChan {
			if evt.Event == "code" {
				fmt.Println("\nScan this QR code with WhatsApp:")
				qrterminal.GenerateHalfBlock(evt.Code, qrterminal.L, os.Stdout)
				fmt.Println()
			} else {
				fmt.Printf("QR channel event: %s\n", evt.Event)
			}
		}
	} else {
		// Already logged in
		err := b.client.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
	}

	return nil
}

// Disconnect cleanly disconnects from WhatsApp
func (b *Bridge) Disconnect() {
	if b.client != nil {
		b.client.Disconnect()
	}
}

// handleEvent processes WhatsApp events
func (b *Bridge) handleEvent(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		b.handleMessage(v)
	case *events.Connected:
		fmt.Println("✓ Connected to WhatsApp")
	case *events.Disconnected:
		fmt.Println("✗ Disconnected from WhatsApp")
	case *events.LoggedOut:
		fmt.Println("✗ Logged out from WhatsApp")
	}
}

// handleMessage processes incoming WhatsApp messages
func (b *Bridge) handleMessage(msg *events.Message) {
	// Skip messages from ourselves
	if msg.Info.IsFromMe {
		return
	}

	// Get the sender JID
	sender := msg.Info.Sender.User

	// Get the message text
	var text string
	if msg.Message.Conversation != nil {
		text = *msg.Message.Conversation
	} else if msg.Message.ExtendedTextMessage != nil && msg.Message.ExtendedTextMessage.Text != nil {
		text = *msg.Message.ExtendedTextMessage.Text
	} else {
		// Not a text message
		return
	}

	// Check if we have a session for this sender
	sessionID := b.getSessionForJID(sender)
	if sessionID == "" {
		// No session, just pass through as normal message
		if b.onMessage != nil {
			b.onMessage(sender, text, false)
		}
		return
	}

	// Try to decode the message
	ctx := context.Background()
	decoded, err := b.stegoClient.DecodeMessage(ctx, &pb.DecodeMessageRequest{
		SessionId: sessionID,
		CoverText: text,
	})
	if err != nil {
		// Decoding failed, treat as normal message
		if b.onMessage != nil {
			b.onMessage(sender, text, false)
		}
		return
	}

	// Successfully decoded
	if b.onMessage != nil {
		b.onMessage(sender, decoded.SecretMessage, true)
	}
}

// SendMessage sends a steganographic message
func (b *Bridge) SendMessage(ctx context.Context, jid string, secretMessage, decoyMessage, topic string) error {
	sessionID := b.getSessionForJID(jid)
	if sessionID == "" {
		return fmt.Errorf("no session found for %s - use /register first", jid)
	}

	// Encode the message
	encoded, err := b.stegoClient.EncodeMessage(ctx, &pb.EncodeMessageRequest{
		SessionId:     sessionID,
		SecretMessage: secretMessage,
		DecoyMessage:  decoyMessage,
		TopicHint:     topic,
	})
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	// Parse the JID
	targetJID, err := types.ParseJID(jid + "@s.whatsapp.net")
	if err != nil {
		return fmt.Errorf("invalid JID: %w", err)
	}

	// Create the message
	waMsg := &waE2E.Message{
		Conversation: proto.String(encoded.CoverText),
	}

	// Send via WhatsApp
	_, err = b.client.SendMessage(ctx, targetJID, waMsg)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	fmt.Printf("📤 Sent stego message to %s (%d bits encoded)\n", jid, encoded.BitsEncoded)
	return nil
}

// SendPlainMessage sends a regular (non-stego) message
func (b *Bridge) SendPlainMessage(ctx context.Context, jid string, text string) error {
	targetJID, err := types.ParseJID(jid + "@s.whatsapp.net")
	if err != nil {
		return fmt.Errorf("invalid JID: %w", err)
	}

	waMsg := &waE2E.Message{
		Conversation: proto.String(text),
	}

	_, err = b.client.SendMessage(ctx, targetJID, waMsg)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	fmt.Printf("📤 Sent plain message to %s\n", jid)
	return nil
}

// RegisterSession maps a WhatsApp JID to a stego session
func (b *Bridge) RegisterSession(jid, sessionID string) {
	b.sessionMap[jid] = sessionID
	fmt.Printf("✓ Registered session %s for %s\n", sessionID[:8], jid)
}

// UnregisterSession removes the JID -> session mapping
func (b *Bridge) UnregisterSession(jid string) {
	delete(b.sessionMap, jid)
	fmt.Printf("✓ Unregistered session for %s\n", jid)
}

// ListSessions shows all registered sessions
func (b *Bridge) ListSessions() {
	if len(b.sessionMap) == 0 {
		fmt.Println("No sessions registered")
		return
	}
	fmt.Println("Registered sessions:")
	for jid, sessionID := range b.sessionMap {
		fmt.Printf("  %s -> %s\n", jid, sessionID[:8])
	}
}

// getSessionForJID looks up the session ID for a JID
func (b *Bridge) getSessionForJID(jid string) string {
	return b.sessionMap[jid]
}

// GetJID returns our WhatsApp JID
func (b *Bridge) GetJID() string {
	if b.client.Store.ID == nil {
		return ""
	}
	return b.client.Store.ID.User
}

// IsConnected returns true if connected to WhatsApp
func (b *Bridge) IsConnected() bool {
	return b.client.IsConnected()
}

// RunInteractive runs an interactive command loop
func (b *Bridge) RunInteractive(ctx context.Context) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("\nCommands:")
	fmt.Println("  /register <phone> <session-id>           Register stego session")
	fmt.Println("  /unregister <phone>                      Unregister session")
	fmt.Println("  /send <phone> <secret> [--decoy <msg>]   Send stego message")
	fmt.Println("  /plain <phone> <message>                 Send plain message")
	fmt.Println("  /sessions                                List registered sessions")
	fmt.Println("  /help                                    Show this help")
	fmt.Println("  /quit                                    Exit")
	fmt.Println()

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if !strings.HasPrefix(line, "/") {
			fmt.Println("Commands must start with /")
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]

		switch cmd {
		case "/quit", "/exit", "/q":
			return

		case "/help", "/h":
			fmt.Println("Commands:")
			fmt.Println("  /register <phone> <session-id>")
			fmt.Println("  /unregister <phone>")
			fmt.Println("  /send <phone> <secret>")
			fmt.Println("  /plain <phone> <message>")
			fmt.Println("  /sessions")
			fmt.Println("  /quit")

		case "/register":
			if len(parts) < 3 {
				fmt.Println("Usage: /register <phone> <session-id>")
				continue
			}
			b.RegisterSession(parts[1], parts[2])

		case "/unregister":
			if len(parts) < 2 {
				fmt.Println("Usage: /unregister <phone>")
				continue
			}
			b.UnregisterSession(parts[1])

		case "/sessions":
			b.ListSessions()

		case "/send":
			if len(parts) < 3 {
				fmt.Println("Usage: /send <phone> <secret-message>")
				continue
			}
			phone := parts[1]
			secret := strings.Join(parts[2:], " ")
			if err := b.SendMessage(ctx, phone, secret, "", "casual chat"); err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		case "/plain":
			if len(parts) < 3 {
				fmt.Println("Usage: /plain <phone> <message>")
				continue
			}
			phone := parts[1]
			msg := strings.Join(parts[2:], " ")
			if err := b.SendPlainMessage(ctx, phone, msg); err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		default:
			fmt.Printf("Unknown command: %s\n", cmd)
		}
	}
}
