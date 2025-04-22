// filepath: /home/jony/Project/decentralize-wikileaks/internal/onion/protocol.go
package onion

import (
	"bufio" // Added for buffered I/O
	"bytes"
	"encoding/gob"
	"fmt"
	"io" // Added for WriteGob/ReadGob

	// Removed UUID import
	// "github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/peer"
)

// CircuitID is now uuid.UUID
// type CircuitID [CircuitIDLength]byte // Replaced by uuid.UUID

// Constants
const (
	// Protocol IDs for libp2p streams
	CircuitSetupProtocol    = "/wikileaks/onion-circuit-setup/1.0.0"
	CircuitTeardownProtocol = "/wikileaks/onion-circuit-teardown/1.0.0" // Keep for explicit teardown
	RelayProtocol           = "/wikileaks/onion-relay/1.0.0"
	TargetServiceProtocol   = "/wikileaks/onion-target-service/1.0.0" // Protocol for the final destination service

	// Sizes
	KeySize = 32 // bytes, for Curve25519 keys
	// CircuitIDLength = 8  // bytes - Removed, using UUID

	// Circuit Setup Status constants (Used in CircuitSetupResponse)
	StatusOK    = 0
	StatusError = 1
	// Add other status codes as needed
)

// Message types for CircuitSetupProtocol
const (
	TypeEstablish   uint8 = 1 // Client -> R1: Start circuit, send PubKey
	TypeEstablished uint8 = 2 // R1 -> Client: Confirm, send R1_PubKey, CircuitID
	TypeExtend      uint8 = 3 // Client -> R(i-1): Extend circuit, send Encrypted(Ri_PeerID + Client_PubKey_for_Ri)
	TypeExtended    uint8 = 4 // R(i-1) -> Client: Confirm extension, send Encrypted(Ri_PubKey)
	TypeTeardown    uint8 = 5 // Client -> R1: Signal circuit teardown
)

// Message types for InnerPayload (Keep separate for clarity)
// Renaming to avoid potential conflicts if constants were global
const (
	MessageTypePublishDocument uint = 1 // Using uint to match test expectation
	MessageTypeRequestBlock    uint = 2
	MessageTypeResponse        uint = 3
	MessageTypeAnnouncement    uint = 4
	MessageTypeError           uint = 5
)

// CircuitSetupMessage is used for establishing and extending circuits.
type CircuitSetupMessage struct {
	Type              uint8   // TypeEstablish or TypeExtend
	CircuitID         string  // Identifies the circuit being built/extended (Changed to string)
	PublicKey         []byte  // Client's ephemeral public key for DH exchange
	NextHopPeerID     peer.ID // For TypeEstablish: The peer ID of the *next* relay (R2) if known. For TypeExtend: The peer ID of the target relay (Ri)
	NextNextHopPeerID peer.ID // For TypeExtend: The peer ID of the hop *after* the target relay (Ri+1) [NEW]
}

// ExtendPayload is the structure encrypted within TypeExtend message's encrypted part
// Note: This seems redundant now with fields in CircuitSetupMessage, but let's keep for potential future use or remove later.
// type ExtendPayload struct {
// 	NextHopPeerID peer.ID       // The peer ID of the next relay (Ri)
// 	ClientPubKey  [KeySize]byte // The client's ephemeral public key for Ri
// }

// CircuitSetupResponse is used for confirming establishment or extension.
type CircuitSetupResponse struct {
	Type      uint8  // TypeEstablished or TypeExtended (mirrors request type + 1?) - Let's use explicit types
	CircuitID string // Identifies the circuit (Changed to string)
	Status    uint8  // StatusOK or StatusError
	PublicKey []byte // For TypeEstablished/TypeExtended: Relay's ephemeral public key for DH
	// Payload []byte // Replaced by specific fields
}

// CircuitTeardownMessage represents a message to close a circuit
type CircuitTeardownMessage struct {
	CircuitID string // Use string
	Reason    string
}

// --- Generic Gob Encoding/Decoding Helpers ---

// WriteGob encodes and writes an interface{} value to the writer using buffered I/O.
func WriteGob(w io.Writer, data interface{}) error {
	// Wrap the writer with a buffered writer
	bw := bufio.NewWriter(w)
	enc := gob.NewEncoder(bw)
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("failed to encode gob: %w", err)
	}
	// Flush the buffer to ensure data is written to the underlying writer
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("failed to flush buffer after gob encode: %w", err)
	}
	return nil
}

// ReadGob reads and decodes data from the reader into the provided interface{} using buffered I/O.
func ReadGob(r io.Reader, data interface{}) error {
	// Wrap the reader with a buffered reader
	br := bufio.NewReader(r)
	dec := gob.NewDecoder(br)
	if err := dec.Decode(data); err != nil {
		// Check specifically for EOF which might be expected in some cases
		if err == io.EOF {
			return io.EOF // Propagate EOF clearly
		}
		return fmt.Errorf("failed to decode gob: %w", err)
	}
	return nil
}

// --- Specific Encoding/Decoding (Optional, if needed for clarity/validation) ---
// You can keep the specific functions if you prefer, but the generic ones above work.

// EncodeCircuitSetupMessage serializes a CircuitSetupMessage.
func EncodeCircuitSetupMessage(msg *CircuitSetupMessage) ([]byte, error) {
	var buf bytes.Buffer
	err := WriteGob(&buf, msg)
	return buf.Bytes(), err
}

// DecodeCircuitSetupMessage deserializes a CircuitSetupMessage.
func DecodeCircuitSetupMessage(data []byte) (*CircuitSetupMessage, error) {
	var msg CircuitSetupMessage
	err := ReadGob(bytes.NewReader(data), &msg)
	return &msg, err
}

// EncodeCircuitSetupResponse serializes a CircuitSetupResponse.
func EncodeCircuitSetupResponse(resp *CircuitSetupResponse) ([]byte, error) {
	var buf bytes.Buffer
	err := WriteGob(&buf, resp)
	return buf.Bytes(), err
}

// DecodeCircuitSetupResponse deserializes a CircuitSetupResponse.
func DecodeCircuitSetupResponse(data []byte) (*CircuitSetupResponse, error) {
	var resp CircuitSetupResponse
	err := ReadGob(bytes.NewReader(data), &resp)
	return &resp, err
}

// EncodeCircuitTeardownMessage serializes a CircuitTeardownMessage.
func EncodeCircuitTeardownMessage(msg *CircuitTeardownMessage) ([]byte, error) {
	var buf bytes.Buffer
	err := WriteGob(&buf, msg)
	return buf.Bytes(), err
}

// DecodeCircuitTeardownMessage deserializes a CircuitTeardownMessage.
func DecodeCircuitTeardownMessage(data []byte) (*CircuitTeardownMessage, error) {
	var msg CircuitTeardownMessage
	err := ReadGob(bytes.NewReader(data), &msg)
	return &msg, err
}
