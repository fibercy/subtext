package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func setupTestDB(t *testing.T) (*Store, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "stegochat-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := New(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create store: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return store, cleanup
}

func TestCreateAndGetSession(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	session := &Session{
		ID:          uuid.New().String(),
		PeerID:      "peer-123",
		DisplayName: "Test Session",
		State:       SessionStatePendingKeyExchange,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	keys := &KeyData{
		SessionID:  session.ID,
		PrivateKey: []byte("test-private-key-32-bytes-long!!"),
		PublicKey:  []byte("test-public-key-32-bytes-long!!!"),
		SharedKey:  nil,
	}

	err := store.CreateSession(session, keys)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Retrieve the session
	retrieved, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if retrieved.ID != session.ID {
		t.Errorf("ID mismatch: got %s, want %s", retrieved.ID, session.ID)
	}
	if retrieved.PeerID != session.PeerID {
		t.Errorf("PeerID mismatch: got %s, want %s", retrieved.PeerID, session.PeerID)
	}
	if retrieved.DisplayName != session.DisplayName {
		t.Errorf("DisplayName mismatch: got %s, want %s", retrieved.DisplayName, session.DisplayName)
	}
	if retrieved.State != session.State {
		t.Errorf("State mismatch: got %v, want %v", retrieved.State, session.State)
	}
}

func TestGetSessionNotFound(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := store.GetSession("non-existent-id")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got %v", err)
	}
}

func TestListSessions(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	// Create 5 sessions
	for i := 0; i < 5; i++ {
		session := &Session{
			ID:          uuid.New().String(),
			PeerID:      "peer-" + string(rune('A'+i)),
			DisplayName: "Session " + string(rune('A'+i)),
			State:       SessionStateActive,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now().Add(time.Duration(i) * time.Minute),
		}
		keys := &KeyData{
			SessionID:  session.ID,
			PrivateKey: []byte("test-private-key-32-bytes-long!!"),
			PublicKey:  []byte("test-public-key-32-bytes-long!!!"),
		}
		if err := store.CreateSession(session, keys); err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
	}

	// List with pagination
	sessions, total, err := store.ListSessions(3, 0)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if total != 5 {
		t.Errorf("Total mismatch: got %d, want 5", total)
	}
	if len(sessions) != 3 {
		t.Errorf("Sessions count mismatch: got %d, want 3", len(sessions))
	}

	// List second page
	sessions, _, err = store.ListSessions(3, 3)
	if err != nil {
		t.Fatalf("ListSessions (page 2) failed: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("Sessions count mismatch for page 2: got %d, want 2", len(sessions))
	}
}

func TestUpdateSessionState(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	session := &Session{
		ID:          uuid.New().String(),
		PeerID:      "peer-123",
		DisplayName: "Test Session",
		State:       SessionStatePendingKeyExchange,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	keys := &KeyData{
		SessionID:  session.ID,
		PrivateKey: []byte("test-private-key-32-bytes-long!!"),
		PublicKey:  []byte("test-public-key-32-bytes-long!!!"),
	}

	if err := store.CreateSession(session, keys); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Update state
	if err := store.UpdateSessionState(session.ID, SessionStateActive); err != nil {
		t.Fatalf("UpdateSessionState failed: %v", err)
	}

	// Verify state changed
	retrieved, err := store.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if retrieved.State != SessionStateActive {
		t.Errorf("State not updated: got %v, want %v", retrieved.State, SessionStateActive)
	}
}

func TestKeysOperations(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	session := &Session{
		ID:          uuid.New().String(),
		PeerID:      "peer-123",
		DisplayName: "Test Session",
		State:       SessionStatePendingKeyExchange,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	keys := &KeyData{
		SessionID:  session.ID,
		PrivateKey: []byte("test-private-key-32-bytes-long!!"),
		PublicKey:  []byte("test-public-key-32-bytes-long!!!"),
	}

	if err := store.CreateSession(session, keys); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Get keys
	retrieved, err := store.GetKeys(session.ID)
	if err != nil {
		t.Fatalf("GetKeys failed: %v", err)
	}
	if string(retrieved.PrivateKey) != string(keys.PrivateKey) {
		t.Errorf("PrivateKey mismatch")
	}
	if retrieved.SharedKey != nil {
		t.Errorf("SharedKey should be nil initially")
	}

	// Update shared key
	sharedKey := []byte("shared-secret-key-32-bytes-long!")
	if err := store.UpdateSharedKey(session.ID, sharedKey); err != nil {
		t.Fatalf("UpdateSharedKey failed: %v", err)
	}

	// Verify shared key
	retrieved, err = store.GetKeys(session.ID)
	if err != nil {
		t.Fatalf("GetKeys after update failed: %v", err)
	}
	if string(retrieved.SharedKey) != string(sharedKey) {
		t.Errorf("SharedKey mismatch after update")
	}
}

func TestDecoyKeys(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	session := &Session{
		ID:          uuid.New().String(),
		PeerID:      "peer-123",
		DisplayName: "Test Session",
		State:       SessionStateActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	keys := &KeyData{
		SessionID:  session.ID,
		PrivateKey: []byte("test-private-key-32-bytes-long!!"),
		PublicKey:  []byte("test-public-key-32-bytes-long!!!"),
	}

	if err := store.CreateSession(session, keys); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Add decoy keys
	decoyKey1 := []byte("decoy-key-1")
	decoyKey2 := []byte("decoy-key-2")

	if err := store.AddDecoyKey(session.ID, decoyKey1, "innocent message 1"); err != nil {
		t.Fatalf("AddDecoyKey 1 failed: %v", err)
	}
	if err := store.AddDecoyKey(session.ID, decoyKey2, "innocent message 2"); err != nil {
		t.Fatalf("AddDecoyKey 2 failed: %v", err)
	}

	// Get decoy keys
	decoys, err := store.GetDecoyKeys(session.ID)
	if err != nil {
		t.Fatalf("GetDecoyKeys failed: %v", err)
	}
	if len(decoys) != 2 {
		t.Errorf("Decoy keys count mismatch: got %d, want 2", len(decoys))
	}
}

func TestDeleteSession(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	session := &Session{
		ID:          uuid.New().String(),
		PeerID:      "peer-123",
		DisplayName: "Test Session",
		State:       SessionStateActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	keys := &KeyData{
		SessionID:  session.ID,
		PrivateKey: []byte("test-private-key-32-bytes-long!!"),
		PublicKey:  []byte("test-public-key-32-bytes-long!!!"),
	}

	if err := store.CreateSession(session, keys); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Delete
	if err := store.DeleteSession(session.ID); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	// Verify deleted
	_, err := store.GetSession(session.ID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound after delete, got %v", err)
	}

	// Keys should also be deleted (cascade)
	_, err = store.GetKeys(session.ID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound for keys after delete, got %v", err)
	}
}
