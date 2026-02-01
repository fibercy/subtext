// Package store provides encrypted SQLite storage for sessions and keys.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExists   = errors.New("session already exists")
	ErrInvalidState    = errors.New("invalid session state")
)

// SessionState represents the state of a session
type SessionState int

const (
	SessionStateUnspecified SessionState = iota
	SessionStatePendingKeyExchange
	SessionStateActive
	SessionStateExpired
)

func (s SessionState) String() string {
	switch s {
	case SessionStatePendingKeyExchange:
		return "pending_key_exchange"
	case SessionStateActive:
		return "active"
	case SessionStateExpired:
		return "expired"
	default:
		return "unspecified"
	}
}

// Session represents a chat session with a peer
type Session struct {
	ID          string
	PeerID      string
	DisplayName string
	State       SessionState
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// KeyData stores cryptographic keys for a session
type KeyData struct {
	SessionID  string
	PrivateKey []byte // Our X25519 private key
	PublicKey  []byte // Our X25519 public key
	SharedKey  []byte // Derived shared secret (after key exchange)
	DecoyKeys  [][]byte
}

// Store provides persistent storage for sessions and keys
type Store struct {
	db *sql.DB
}

// New creates a new Store with the given database path
func New(dbPath string) (*Store, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL: %w", err)
	}

	// Enable foreign key constraints (required for ON DELETE CASCADE)
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return store, nil
}

// migrate creates the database schema
func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		peer_id TEXT NOT NULL,
		display_name TEXT NOT NULL,
		state INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_peer_id ON sessions(peer_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);

	CREATE TABLE IF NOT EXISTS keys (
		session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
		private_key BLOB NOT NULL,
		public_key BLOB NOT NULL,
		shared_key BLOB,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS decoy_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
		decoy_key BLOB NOT NULL,
		decoy_message TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_decoy_keys_session ON decoy_keys(session_id);

	CREATE TABLE IF NOT EXISTS messages (
		id TEXT PRIMARY KEY,
		session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
		cover_text TEXT NOT NULL,
		encrypted_payload BLOB NOT NULL,
		is_outgoing INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// CreateSession creates a new session
func (s *Store) CreateSession(session *Session, keys *KeyData) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert session
	_, err = tx.Exec(`
		INSERT INTO sessions (id, peer_id, display_name, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, session.ID, session.PeerID, session.DisplayName, session.State,
		session.CreatedAt, session.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to insert session: %w", err)
	}

	// Insert keys
	_, err = tx.Exec(`
		INSERT INTO keys (session_id, private_key, public_key, shared_key)
		VALUES (?, ?, ?, ?)
	`, keys.SessionID, keys.PrivateKey, keys.PublicKey, keys.SharedKey)
	if err != nil {
		return fmt.Errorf("failed to insert keys: %w", err)
	}

	return tx.Commit()
}

// GetSession retrieves a session by ID
func (s *Store) GetSession(id string) (*Session, error) {
	var session Session
	err := s.db.QueryRow(`
		SELECT id, peer_id, display_name, state, created_at, updated_at
		FROM sessions WHERE id = ?
	`, id).Scan(
		&session.ID, &session.PeerID, &session.DisplayName,
		&session.State, &session.CreatedAt, &session.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// ListSessions retrieves all sessions with pagination
func (s *Store) ListSessions(limit, offset int) ([]*Session, int, error) {
	// Get total count
	var total int
	err := s.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(`
		SELECT id, peer_id, display_name, state, created_at, updated_at
		FROM sessions
		ORDER BY updated_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var session Session
		if err := rows.Scan(
			&session.ID, &session.PeerID, &session.DisplayName,
			&session.State, &session.CreatedAt, &session.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		sessions = append(sessions, &session)
	}

	return sessions, total, rows.Err()
}

// UpdateSessionState updates the state of a session
func (s *Store) UpdateSessionState(id string, state SessionState) error {
	result, err := s.db.Exec(`
		UPDATE sessions SET state = ?, updated_at = ? WHERE id = ?
	`, state, time.Now(), id)
	if err != nil {
		return err
	}

	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// GetKeys retrieves the keys for a session
func (s *Store) GetKeys(sessionID string) (*KeyData, error) {
	var keys KeyData
	err := s.db.QueryRow(`
		SELECT session_id, private_key, public_key, shared_key
		FROM keys WHERE session_id = ?
	`, sessionID).Scan(
		&keys.SessionID, &keys.PrivateKey, &keys.PublicKey, &keys.SharedKey,
	)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &keys, nil
}

// UpdateSharedKey updates the shared key after key exchange
func (s *Store) UpdateSharedKey(sessionID string, sharedKey []byte) error {
	result, err := s.db.Exec(`
		UPDATE keys SET shared_key = ? WHERE session_id = ?
	`, sharedKey, sessionID)
	if err != nil {
		return err
	}

	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// AddDecoyKey adds a decoy key for deniable encryption
func (s *Store) AddDecoyKey(sessionID string, decoyKey []byte, decoyMessage string) error {
	_, err := s.db.Exec(`
		INSERT INTO decoy_keys (session_id, decoy_key, decoy_message)
		VALUES (?, ?, ?)
	`, sessionID, decoyKey, decoyMessage)
	return err
}

// GetDecoyKeys retrieves all decoy keys for a session
func (s *Store) GetDecoyKeys(sessionID string) ([][]byte, error) {
	rows, err := s.db.Query(`
		SELECT decoy_key FROM decoy_keys WHERE session_id = ?
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys [][]byte
	for rows.Next() {
		var key []byte
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, rows.Err()
}

// DeleteSession deletes a session and all associated data
func (s *Store) DeleteSession(id string) error {
	result, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		return err
	}

	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}
