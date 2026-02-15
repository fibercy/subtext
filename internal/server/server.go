// Package server implements the gRPC StegoService.
package server

import (
	"context"
	"sync"
	"time"

	"github.com/cy/subtext/internal/crypto"
	"github.com/cy/subtext/internal/deniable"
	"github.com/cy/subtext/internal/llm"
	"github.com/cy/subtext/internal/subtext"
	"github.com/cy/subtext/internal/store"
	pb "github.com/cy/subtext/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StegoServer implements the StegoService gRPC server
type StegoServer struct {
	pb.UnimplementedStegoServiceServer
	store   *store.Store
	encoder *subtext.Encoder
	decoder *subtext.Decoder
	flowsMu sync.Mutex
	flows   map[string]*interactiveEncodeFlow
}

const MaxPlaintextLengthNoDecoy = 512

// InteractiveChunkSize is set to match subtext.TargetSegmentPayloadLength

type interactiveEncodeFlow struct {
	SessionID string
	Topic     string
	Chunks    [][]byte
	NextIndex int
	Attempts  []int // per-segment encoder attempt numbers (1-based)
}

// ServerOption configures the server
type ServerOption func(*StegoServer)

// WithLLMClient sets the LLM client for encoding/decoding
func WithLLMClient(client *llm.Client) ServerOption {
	return func(s *StegoServer) {
		s.encoder = subtext.NewEncoder(client)
		s.decoder = subtext.NewDecoder(client)
	}
}

// New creates a new StegoServer
func New(st *store.Store, opts ...ServerOption) *StegoServer {
	s := &StegoServer{
		store: st,
		flows: make(map[string]*interactiveEncodeFlow),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// CreateSession creates a new session with a peer
func (s *StegoServer) CreateSession(ctx context.Context, req *pb.CreateSessionRequest) (*pb.Session, error) {
	if req.PeerId == "" {
		return nil, status.Error(codes.InvalidArgument, "peer_id is required")
	}

	// Generate key pair for this session
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key pair: %v", err)
	}

	now := time.Now()
	sessionID := uuid.New().String()

	session := &store.Session{
		ID:          sessionID,
		PeerID:      req.PeerId,
		DisplayName: req.DisplayName,
		State:       store.SessionStatePendingKeyExchange,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	keys := &store.KeyData{
		SessionID:  sessionID,
		PrivateKey: keyPair.PrivateKey[:],
		PublicKey:  keyPair.PublicKey[:],
	}

	if err := s.store.CreateSession(session, keys); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create session: %v", err)
	}

	return sessionToProto(session), nil
}

// GetSession retrieves a session by ID
func (s *StegoServer) GetSession(ctx context.Context, req *pb.GetSessionRequest) (*pb.Session, error) {
	if req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}

	session, err := s.store.GetSession(req.SessionId)
	if err == store.ErrSessionNotFound {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get session: %v", err)
	}

	return sessionToProto(session), nil
}

// ListSessions lists all sessions with pagination
func (s *StegoServer) ListSessions(ctx context.Context, req *pb.ListSessionsRequest) (*pb.ListSessionsResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	offset := int(req.Offset)
	if offset < 0 {
		offset = 0
	}

	sessions, total, err := s.store.ListSessions(limit, offset)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list sessions: %v", err)
	}

	pbSessions := make([]*pb.Session, len(sessions))
	for i, session := range sessions {
		pbSessions[i] = sessionToProto(session)
	}

	return &pb.ListSessionsResponse{
		Sessions: pbSessions,
		Total:    int32(total),
	}, nil
}

// InitiateKeyExchange starts the key exchange process
func (s *StegoServer) InitiateKeyExchange(ctx context.Context, req *pb.InitiateKeyExchangeRequest) (*pb.InitiateKeyExchangeResponse, error) {
	if req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}

	// Get the session's public key
	keys, err := s.store.GetKeys(req.SessionId)
	if err == store.ErrSessionNotFound {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get keys: %v", err)
	}

	return &pb.InitiateKeyExchangeResponse{
		PublicKey:     keys.PublicKey,
		KeyExchangeId: req.SessionId, // Use session ID as key exchange ID
	}, nil
}

// CompleteKeyExchange completes the key exchange with peer's public key
func (s *StegoServer) CompleteKeyExchange(ctx context.Context, req *pb.CompleteKeyExchangeRequest) (*pb.CompleteKeyExchangeResponse, error) {
	if req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if len(req.PeerPublicKey) != crypto.KeySize {
		return nil, status.Error(codes.InvalidArgument, "invalid peer public key size")
	}

	// Get our keys
	keys, err := s.store.GetKeys(req.SessionId)
	if err == store.ErrSessionNotFound {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get keys: %v", err)
	}

	// Compute shared secret
	sharedKey, err := crypto.ComputeSharedSecret(keys.PrivateKey, req.PeerPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "key exchange failed: %v", err)
	}

	// Store the shared key
	if err := s.store.UpdateSharedKey(req.SessionId, sharedKey); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store shared key: %v", err)
	}

	// Update session state to active
	if err := s.store.UpdateSessionState(req.SessionId, store.SessionStateActive); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update session state: %v", err)
	}

	return &pb.CompleteKeyExchangeResponse{
		Success: true,
	}, nil
}

// EncodeMessage encodes a secret message into cover text
func (s *StegoServer) EncodeMessage(ctx context.Context, req *pb.EncodeMessageRequest) (*pb.EncodeMessageResponse, error) {
	if req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if req.SecretMessage == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_message is required")
	}
	if req.DecoyMessage != "" {
		if len(req.SecretMessage) > deniable.MaxPayloadSize {
			return nil, status.Errorf(codes.InvalidArgument, "secret_message too long for decoy mode (max %d chars)", deniable.MaxPayloadSize)
		}
		if len(req.DecoyMessage) > deniable.MaxPayloadSize {
			return nil, status.Errorf(codes.InvalidArgument, "decoy_message too long (max %d chars)", deniable.MaxPayloadSize)
		}
	} else if len(req.SecretMessage) > MaxPlaintextLengthNoDecoy {
		return nil, status.Errorf(codes.InvalidArgument, "secret_message too long (max %d chars without decoy)", MaxPlaintextLengthNoDecoy)
	}

	// Get the shared key
	keys, err := s.store.GetKeys(req.SessionId)
	if err == store.ErrSessionNotFound {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get keys: %v", err)
	}
	if keys.SharedKey == nil {
		return nil, status.Error(codes.FailedPrecondition, "key exchange not completed")
	}

	var payload []byte
	var decoyKeyToStore []byte

	// Check if deniable encryption is requested
	if req.DecoyMessage != "" {
		// Use deniable encryption
		enc := deniable.New()
		msg := deniable.Message{
			RealMessage:  req.SecretMessage,
			DecoyMessage: req.DecoyMessage,
		}

		result, err := enc.Encrypt(keys.SharedKey, msg)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "deniable encryption failed: %v", err)
		}

		payload = result.Ciphertext
		decoyKeyToStore = result.DecoyKey

		// Store the decoy key for later retrieval
		if err := s.store.AddDecoyKey(req.SessionId, decoyKeyToStore, req.DecoyMessage); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to store decoy key: %v", err)
		}
	} else {
		// Standard encryption with reduced overhead
		ciphertext, err := crypto.CompactEncrypt(keys.SharedKey, []byte(req.SecretMessage))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "encryption failed: %v", err)
		}
		payload = ciphertext
	}

	// Check if LLM encoder is available
	if s.encoder == nil {
		// Fallback: return placeholder with bit count
		bitsToEncode := len(payload) * 8
		return &pb.EncodeMessageResponse{
			CoverText:   "[LLM not configured - start Ollama with qwen2.5:14b]",
			BitsEncoded: int32(bitsToEncode),
			MessageId:   uuid.New().String(),
		}, nil
	}

	// Use LLM to generate cover text that embeds the payload
	topic := req.TopicHint
	if topic == "" {
		topic = "weekend plans"
	}

	result, err := s.encoder.Encode(ctx, payload, topic)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encoding failed: %v", err)
	}

	return &pb.EncodeMessageResponse{
		CoverText:   result.CoverText,
		BitsEncoded: int32(result.BitsEncoded),
		MessageId:   uuid.New().String(),
	}, nil
}

// StartInteractiveEncode starts a multi-turn stego flow and returns the first cover segment.
func (s *StegoServer) StartInteractiveEncode(ctx context.Context, req *pb.StartInteractiveEncodeRequest) (*pb.StartInteractiveEncodeResponse, error) {
	if req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if req.SecretMessage == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_message is required")
	}
	if len(req.SecretMessage) > MaxPlaintextLengthNoDecoy {
		return nil, status.Errorf(codes.InvalidArgument, "secret_message too long (max %d chars)", MaxPlaintextLengthNoDecoy)
	}
	if s.encoder == nil {
		return nil, status.Error(codes.FailedPrecondition, "LLM encoder not configured")
	}

	keys, err := s.store.GetKeys(req.SessionId)
	if err == store.ErrSessionNotFound {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get keys: %v", err)
	}
	if keys.SharedKey == nil {
		return nil, status.Error(codes.FailedPrecondition, "key exchange not completed")
	}

	ciphertext, err := crypto.CompactEncrypt(keys.SharedKey, []byte(req.SecretMessage))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encryption failed: %v", err)
	}
	chunks := chunkBytes(ciphertext, subtext.TargetSegmentPayloadLength)
	if len(chunks) == 0 {
		return nil, status.Error(codes.Internal, "failed to split encrypted payload")
	}

	topic := req.TopicHint
	if topic == "" {
		topic = "weekend plans"
	}

	flowID := uuid.New().String()
	s.flowsMu.Lock()
	s.flows[flowID] = &interactiveEncodeFlow{
		SessionID: req.SessionId,
		Topic:     topic,
		Chunks:    chunks,
		NextIndex: 0,
	}
	s.flowsMu.Unlock()

	next, err := s.nextInteractiveSegment(ctx, flowID, "")
	if err != nil {
		return nil, err
	}
	return &pb.StartInteractiveEncodeResponse{
		FlowId:        next.FlowId,
		CoverText:     next.CoverText,
		SegmentIndex:  next.SegmentIndex,
		TotalSegments: next.TotalSegments,
		Done:          next.Done,
		EncodeAttempt: next.EncodeAttempt,
	}, nil
}

// ContinueInteractiveEncode continues an existing flow using the peer's plain reply as context.
func (s *StegoServer) ContinueInteractiveEncode(ctx context.Context, req *pb.ContinueInteractiveEncodeRequest) (*pb.ContinueInteractiveEncodeResponse, error) {
	if req.FlowId == "" {
		return nil, status.Error(codes.InvalidArgument, "flow_id is required")
	}
	return s.nextInteractiveSegment(ctx, req.FlowId, req.PeerReply)
}

func (s *StegoServer) nextInteractiveSegment(ctx context.Context, flowID, peerReply string) (*pb.ContinueInteractiveEncodeResponse, error) {
	s.flowsMu.Lock()
	flow, ok := s.flows[flowID]
	if !ok {
		s.flowsMu.Unlock()
		return nil, status.Error(codes.NotFound, "interactive flow not found or already completed")
	}
	if flow.NextIndex >= len(flow.Chunks) {
		delete(s.flows, flowID)
		s.flowsMu.Unlock()
		return nil, status.Error(codes.NotFound, "interactive flow already completed")
	}

	currentIndex := flow.NextIndex
	total := len(flow.Chunks)
	chunk := append([]byte(nil), flow.Chunks[currentIndex]...)
	topic := flow.Topic
	s.flowsMu.Unlock()

	encoded, err := s.encoder.EncodeInteractiveSegment(ctx, chunk, topic, peerReply)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "segment encoding failed: %v", err)
	}

	s.flowsMu.Lock()
	flow, ok = s.flows[flowID]
	if !ok {
		s.flowsMu.Unlock()
		return nil, status.Error(codes.NotFound, "interactive flow not found")
	}
	if flow.NextIndex != currentIndex {
		s.flowsMu.Unlock()
		return nil, status.Error(codes.Aborted, "flow advanced concurrently; retry")
	}
	flow.NextIndex++
	flow.Attempts = append(flow.Attempts, encoded.Attempt)
	done := flow.NextIndex >= len(flow.Chunks)
	if done {
		delete(s.flows, flowID)
	}
	s.flowsMu.Unlock()

	return &pb.ContinueInteractiveEncodeResponse{
		FlowId:        flowID,
		CoverText:     encoded.CoverText,
		SegmentIndex:  int32(currentIndex + 1),
		TotalSegments: int32(total),
		Done:          done,
		EncodeAttempt: int32(encoded.Attempt),
	}, nil
}

func chunkBytes(data []byte, size int) [][]byte {
	if len(data) == 0 || size <= 0 {
		return nil
	}
	chunks := make([][]byte, 0, (len(data)+size-1)/size)
	for i := 0; i < len(data); i += size {
		end := i + size
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, end-i)
		copy(chunk, data[i:end])
		chunks = append(chunks, chunk)
	}
	return chunks
}

// DecodeMessage decodes a secret message from cover text
func (s *StegoServer) DecodeMessage(ctx context.Context, req *pb.DecodeMessageRequest) (*pb.DecodeMessageResponse, error) {
	if req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if req.CoverText == "" {
		return nil, status.Error(codes.InvalidArgument, "cover_text is required")
	}

	// Get the shared key (or decoy key if provided)
	keys, err := s.store.GetKeys(req.SessionId)
	if err == store.ErrSessionNotFound {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get keys: %v", err)
	}

	decryptKey := keys.SharedKey
	isDecoy := false

	if len(req.DecoyKey) > 0 {
		decryptKey = req.DecoyKey
		isDecoy = true
	}

	if decryptKey == nil {
		return nil, status.Error(codes.FailedPrecondition, "key exchange not completed")
	}

	// Check if LLM decoder is available
	if s.decoder == nil {
		return &pb.DecodeMessageResponse{
			SecretMessage: "[LLM not configured - start Ollama with qwen2.5:14b]",
			IsDecoy:       isDecoy,
			MessageId:     uuid.New().String(),
		}, nil
	}

	topic := req.TopicHint
	if topic == "" {
		topic = "weekend plans"
	}

	// Convert proto int32 attempts to []int
	var attempts []int
	if len(req.EncodeAttempts) > 0 {
		attempts = make([]int, len(req.EncodeAttempts))
		for i, a := range req.EncodeAttempts {
			attempts[i] = int(a)
		}
	}

	// Use LLM to extract bits from cover text
	result, err := s.decoder.DecodeWithPeerReplies(ctx, req.CoverText, topic, req.PeerReplies, attempts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decoding failed: %v", err)
	}

	if !result.Valid {
		return nil, status.Error(codes.InvalidArgument, "invalid cover text or corrupted message")
	}

	// Try deniable decryption first (works for both deniable and standard messages)
	dec := deniable.New()
	plaintext, wasDecoy, err := dec.Decrypt(result.EncryptedPayload, decryptKey)
	if err == nil {
		return &pb.DecodeMessageResponse{
			SecretMessage: plaintext,
			IsDecoy:       wasDecoy,
			MessageId:     uuid.New().String(),
		}, nil
	}

	// Fallback: try compact decryption for messages without deniable headers
	standardPlaintext, err := crypto.CompactDecrypt(decryptKey, result.EncryptedPayload)
	if err != nil {
		if isDecoy {
			return nil, status.Error(codes.InvalidArgument, "decoy key does not match this message")
		}
		return nil, status.Errorf(codes.Internal, "decryption failed: %v", err)
	}

	return &pb.DecodeMessageResponse{
		SecretMessage: string(standardPlaintext),
		IsDecoy:       isDecoy,
		MessageId:     uuid.New().String(),
	}, nil
}

// GeneratePeerReply generates a plain conversational reply to a received message.
func (s *StegoServer) GeneratePeerReply(ctx context.Context, req *pb.GeneratePeerReplyRequest) (*pb.GeneratePeerReplyResponse, error) {
	if req.Message == "" {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}
	if s.encoder == nil {
		return nil, status.Error(codes.FailedPrecondition, "LLM encoder not configured")
	}

	topic := req.TopicHint
	if topic == "" {
		topic = "casual chat"
	}

	reply, err := s.encoder.GenerateReply(ctx, req.Message, topic)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reply generation failed: %v", err)
	}

	return &pb.GeneratePeerReplyResponse{
		Reply: reply,
	}, nil
}

// AddDecoyKey adds a decoy key for deniable encryption
func (s *StegoServer) AddDecoyKey(ctx context.Context, req *pb.AddDecoyKeyRequest) (*pb.AddDecoyKeyResponse, error) {
	if req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if req.DecoyMessage == "" {
		return nil, status.Error(codes.InvalidArgument, "decoy_message is required")
	}

	// Verify session exists
	_, err := s.store.GetSession(req.SessionId)
	if err == store.ErrSessionNotFound {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get session: %v", err)
	}

	// Generate a decoy key
	decoyKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate decoy key: %v", err)
	}

	// Store the decoy key
	decoyKey := decoyKeyPair.PrivateKey[:]
	if err := s.store.AddDecoyKey(req.SessionId, decoyKey, req.DecoyMessage); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store decoy key: %v", err)
	}

	return &pb.AddDecoyKeyResponse{
		DecoyKey:   decoyKey,
		DecoyKeyId: uuid.New().String(),
	}, nil
}

// Helper function to convert store.Session to proto.Session
func sessionToProto(s *store.Session) *pb.Session {
	return &pb.Session{
		Id:          s.ID,
		PeerId:      s.PeerID,
		DisplayName: s.DisplayName,
		State:       stateToProto(s.State),
		CreatedAt:   s.CreatedAt.Unix(),
		UpdatedAt:   s.UpdatedAt.Unix(),
	}
}

// Helper function to convert store.SessionState to proto.SessionState
func stateToProto(s store.SessionState) pb.SessionState {
	switch s {
	case store.SessionStatePendingKeyExchange:
		return pb.SessionState_SESSION_STATE_PENDING_KEY_EXCHANGE
	case store.SessionStateActive:
		return pb.SessionState_SESSION_STATE_ACTIVE
	case store.SessionStateExpired:
		return pb.SessionState_SESSION_STATE_EXPIRED
	default:
		return pb.SessionState_SESSION_STATE_UNSPECIFIED
	}
}
