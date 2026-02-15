package subtext

import (
	"encoding/binary"
	"testing"
)

func TestBytesToBits(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected []bool
	}{
		{
			name:     "single byte 0xFF",
			input:    []byte{0xFF},
			expected: []bool{true, true, true, true, true, true, true, true},
		},
		{
			name:     "single byte 0x00",
			input:    []byte{0x00},
			expected: []bool{false, false, false, false, false, false, false, false},
		},
		{
			name:     "single byte 0xAA", // 10101010
			input:    []byte{0xAA},
			expected: []bool{true, false, true, false, true, false, true, false},
		},
		{
			name:     "two bytes",
			input:    []byte{0x0F, 0xF0}, // 00001111 11110000
			expected: []bool{false, false, false, false, true, true, true, true, true, true, true, true, false, false, false, false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := bytesToBits(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("Length mismatch: got %d, want %d", len(result), len(tc.expected))
				return
			}
			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("Bit %d mismatch: got %v, want %v", i, result[i], tc.expected[i])
				}
			}
		})
	}
}

func TestBitsToBytes(t *testing.T) {
	testCases := []struct {
		name     string
		input    []bool
		expected []byte
	}{
		{
			name:     "single byte 0xFF",
			input:    []bool{true, true, true, true, true, true, true, true},
			expected: []byte{0xFF},
		},
		{
			name:     "single byte 0x00",
			input:    []bool{false, false, false, false, false, false, false, false},
			expected: []byte{0x00},
		},
		{
			name:     "single byte 0xAA",
			input:    []bool{true, false, true, false, true, false, true, false},
			expected: []byte{0xAA},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := bitsToBytes(tc.input)
			if len(result) != len(tc.expected) {
				t.Errorf("Length mismatch: got %d, want %d", len(result), len(tc.expected))
				return
			}
			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("Byte %d mismatch: got %02x, want %02x", i, result[i], tc.expected[i])
				}
			}
		})
	}
}

func TestBytesToBitsRoundtrip(t *testing.T) {
	testData := []byte("Hello, World! 🔐")

	bits := bytesToBits(testData)
	if len(bits) != len(testData)*8 {
		t.Errorf("Bits length wrong: got %d, want %d", len(bits), len(testData)*8)
	}

	recovered := bitsToBytes(bits)
	if string(recovered) != string(testData) {
		t.Errorf("Roundtrip failed: got %q, want %q", string(recovered), string(testData))
	}
}

func TestBitsToInt(t *testing.T) {
	testCases := []struct {
		name     string
		bits     []bool
		expected int
	}{
		{"0", []bool{false}, 0},
		{"1", []bool{true}, 1},
		{"00", []bool{false, false}, 0},
		{"01", []bool{false, true}, 1},
		{"10", []bool{true, false}, 2},
		{"11", []bool{true, true}, 3},
		{"1010", []bool{true, false, true, false}, 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := bitsToInt(tc.bits)
			if result != tc.expected {
				t.Errorf("got %d, want %d", result, tc.expected)
			}
		})
	}
}

func TestIntToBits(t *testing.T) {
	testCases := []struct {
		name     string
		n        int
		numBits  int
		expected []bool
	}{
		{"0 in 2 bits", 0, 2, []bool{false, false}},
		{"1 in 2 bits", 1, 2, []bool{false, true}},
		{"2 in 2 bits", 2, 2, []bool{true, false}},
		{"3 in 2 bits", 3, 2, []bool{true, true}},
		{"5 in 3 bits", 5, 3, []bool{true, false, true}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := intToBits(tc.n, tc.numBits)
			if len(result) != len(tc.expected) {
				t.Errorf("Length mismatch: got %d, want %d", len(result), len(tc.expected))
				return
			}
			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("Bit %d mismatch: got %v, want %v", i, result[i], tc.expected[i])
				}
			}
		})
	}
}

func TestIntBitsRoundtrip(t *testing.T) {
	for i := 0; i < 16; i++ {
		bits := intToBits(i, 4)
		recovered := bitsToInt(bits)
		if recovered != i {
			t.Errorf("Roundtrip failed for %d: got %d", i, recovered)
		}
	}
}

func TestComputeChecksum(t *testing.T) {
	data1 := []byte("Hello")
	data2 := []byte("World")

	cs1 := computeChecksum(data1)
	cs2 := computeChecksum(data2)

	if cs1 == cs2 {
		t.Error("Different data should produce different checksums")
	}

	// Same data should produce same checksum
	cs1Again := computeChecksum(data1)
	if cs1 != cs1Again {
		t.Error("Same data should produce same checksum")
	}
}

func TestExtractChunk(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"hello world", "hello "},
		{"  hello world", "hello "},
		{"hello", "hello "},
		{"", ""},
		{"   ", ""},
	}

	for _, tc := range testCases {
		result := extractChunk(tc.input)
		if result != tc.expected {
			t.Errorf("extractChunk(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestBuildPrompt(t *testing.T) {
	prompt := buildPrompt("movies")
	if prompt == "" {
		t.Error("Prompt should not be empty")
	}
	if len(prompt) < 50 {
		t.Error("Prompt should have reasonable length")
	}
}

func TestLengthPrefixEncoding(t *testing.T) {
	// Simulate encoding a payload with 2-byte length prefix
	payload := []byte("secret message")

	// Create length prefix (2 bytes)
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(payload)))

	// Combine and verify
	fullPayload := append(lengthPrefix, payload...)

	// Parse back
	parsedLen := int(binary.BigEndian.Uint16(fullPayload[0:2]))

	if parsedLen != len(payload) {
		t.Errorf("Length mismatch: got %d, want %d", parsedLen, len(payload))
	}

	// Extract payload
	extracted := fullPayload[2 : 2+parsedLen]
	if string(extracted) != string(payload) {
		t.Errorf("Payload mismatch: got %q, want %q", string(extracted), string(payload))
	}
}

func TestSplitCoverSegments(t *testing.T) {
	cover := "first normal message" + segmentSeparator + "second normal message"
	segments := splitCoverSegments(cover)
	if len(segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(segments))
	}
	if segments[0] != "first normal message" {
		t.Fatalf("unexpected first segment: %q", segments[0])
	}
	if segments[1] != "second normal message" {
		t.Fatalf("unexpected second segment: %q", segments[1])
	}
}

func TestIsValidCoverSegment(t *testing.T) {
	valid := "i can meet after work near oak street maybe around seven if traffic is okay"
	if !isValidCoverSegment(valid) {
		t.Fatal("expected valid segment to pass quality checks")
	}

	if isValidCoverSegment("Write One Sentence (Convincer, Closery): include names.") {
		t.Fatal("expected meta/instruction text to be rejected")
	}

	if isValidCoverSegment("line one of message\nline two of message") {
		t.Fatal("expected multi-line segment to be rejected")
	}
}
