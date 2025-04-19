package onion

import (
	"context"
	"encoding/json"

	// "crypto/ecdh" // Using DeriveSharedKey now - Removed import
	"fmt"
	"sync"
	"time"

	// "github.com/sohelahmedjony/decentralize-wikileaks/internal/onion/packet" // Removed incorrect import

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	// DefaultCircuitBuildTimeout is the default timeout for building a circuit.
	DefaultCircuitBuildTimeout = 30 * time.Second
)

// ClientCircuit holds the state for an established client-side circuit.
type ClientCircuit struct {
	ID        string         // Unique identifier for the circuit (e.g., assigned by entry node)
	Path      []peer.ID      // The sequence of relay PeerIDs in the circuit
	Keys      [][]byte       // Symmetric keys shared with each relay in the path (K1, K2, K3...)
	EntryNode peer.ID        // The first node in the path
	ExitNode  peer.ID        // The last node in the path
	CreatedAt time.Time      // Timestamp when the circuit was established
	Stream    network.Stream // The stream to the entry node for sending data/teardown
	mu        sync.RWMutex   // Protects access to circuit state if needed later
}

// CircuitBuilder manages the process of building onion circuits.
type CircuitBuilder struct {
	host host.Host // The libp2p host instance for this client
	opts CircuitBuilderOptions
}

// CircuitBuilderOptions contains configuration options for the CircuitBuilder.
type CircuitBuilderOptions struct {
	CircuitBuildTimeout time.Duration // Timeout for the entire circuit build process
	StreamTimeout       time.Duration // Timeout for individual stream operations (setup, extend)
	// Add other options like preferred relay selection strategy, etc.
}

// DefaultCircuitBuilderOptions returns the default options.
func DefaultCircuitBuilderOptions() CircuitBuilderOptions {
	return CircuitBuilderOptions{
		CircuitBuildTimeout: DefaultCircuitBuildTimeout,
		StreamTimeout:       10 * time.Second, // Shorter timeout for individual steps
	}
}

// NewCircuitBuilder creates a new CircuitBuilder instance.
func NewCircuitBuilder(h host.Host, opts ...CircuitBuilderOption) (*CircuitBuilder, error) {
	options := DefaultCircuitBuilderOptions()
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("failed to apply circuit builder option: %w", err)
		}
	}

	return &CircuitBuilder{
		host: h,
		opts: options,
	}, nil
}

// CircuitBuilderOption defines a function type for configuring CircuitBuilderOptions.
type CircuitBuilderOption func(*CircuitBuilderOptions) error

// WithCircuitBuildTimeout sets the overall timeout for building a circuit.
func WithCircuitBuildTimeout(timeout time.Duration) CircuitBuilderOption {
	return func(opts *CircuitBuilderOptions) error {
		if timeout <= 0 {
			return fmt.Errorf("circuit build timeout must be positive")
		}
		opts.CircuitBuildTimeout = timeout
		return nil
	}
}

// WithStreamTimeout sets the timeout for individual stream operations during circuit build.
func WithStreamTimeout(timeout time.Duration) CircuitBuilderOption {
	return func(opts *CircuitBuilderOptions) error {
		if timeout <= 0 {
			return fmt.Errorf("stream timeout must be positive")
		}
		opts.StreamTimeout = timeout
		return nil
	}
}

// BuildCircuit attempts to establish a new onion circuit through the specified path of relays.
func (cb *CircuitBuilder) BuildCircuit(ctx context.Context, path []peer.ID) (*ClientCircuit, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("circuit path cannot be empty")
	}

	buildCtx, cancel := context.WithTimeout(ctx, cb.opts.CircuitBuildTimeout)
	defer cancel()

	entryNode := path[0]
	exitNode := path[len(path)-1]
	sharedKeys := make([][]byte, len(path)) // K1, K2, K3...

	var currentStream network.Stream
	var err error

	// Step 1: Establish connection and key with the entry node (R1)
	// Generate client's ephemeral keys for this hop
	clientPrivKeyR1, clientPubKeyR1Bytes, err := GenerateEphemeralKeyPair() // Using crypto.go function
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keys for R1: %w", err)
	}

	streamCtx, streamCancel := context.WithTimeout(buildCtx, cb.opts.StreamTimeout)
	currentStream, err = cb.host.NewStream(streamCtx, entryNode, protocol.ID(CircuitSetupProtocol))
	streamCancel()
	if err != nil {
		return nil, fmt.Errorf("failed to open setup stream to entry node %s: %w", entryNode, err)
	}
	// defer currentStream.Close() // Keep stream open for subsequent extend requests and data

	// Send initial setup request (TypeEstablish)
	// Client proposes a CircuitID (e.g., a random string) for R1 to potentially use or replace.
	// Let's generate a simple temporary ID for now. A better approach might be needed.
	proposedCircuitID := fmt.Sprintf("client-%s-%d", cb.host.ID().ShortString(), time.Now().UnixNano())

	setupReq := &CircuitSetupMessage{
		Type:      TypeEstablish,     // Use protocol constant
		CircuitID: proposedCircuitID, // Client proposes an ID - R1 will confirm/replace
		PublicKey: clientPubKeyR1Bytes,
		// NextHopPeerID is not needed for TypeEstablish
	}
	// Use WriteGob from protocol.go
	if err := WriteGob(currentStream, setupReq); err != nil {
		currentStream.Reset() // Close stream on error
		return nil, fmt.Errorf("failed to send setup request to %s: %w", entryNode, err)
	}

	// Receive setup response (TypeEstablished)
	var setupResp CircuitSetupResponse // Use protocol.go struct
	// Use ReadGob from protocol.go
	if err := ReadGob(currentStream, &setupResp); err != nil {
		currentStream.Reset()
		return nil, fmt.Errorf("failed to read setup response from %s: %w", entryNode, err)
	}

	// Check response validity (using constants from protocol.go)
	if setupResp.Type != TypeEstablished || setupResp.Status != StatusOK {
		currentStream.Reset()
		// Try to get error message from PublicKey field if StatusError (assuming error message might be put there)
		errMsg := "setup failed"
		if setupResp.Status == StatusError && len(setupResp.PublicKey) > 0 {
			errMsg = string(setupResp.PublicKey)
		}
		return nil, fmt.Errorf("received error setup response from %s: type=%d, status=%d, msg=%s",
			entryNode, setupResp.Type, setupResp.Status, errMsg)
	}
	if len(setupResp.PublicKey) == 0 {
		currentStream.Reset()
		return nil, fmt.Errorf("entry node %s did not provide public key", entryNode)
	}
	if setupResp.CircuitID == "" {
		currentStream.Reset()
		return nil, fmt.Errorf("entry node %s did not provide CircuitID", entryNode)
	}

	// Compute shared key K1 using DeriveSharedKey from crypto.go
	relayPubKeyR1Bytes := setupResp.PublicKey
	sharedKeyR1, err := DeriveSharedKey(clientPrivKeyR1, relayPubKeyR1Bytes)
	if err != nil {
		currentStream.Reset()
		return nil, fmt.Errorf("failed to compute shared secret with entry node %s: %w", entryNode, err)
	}
	sharedKeys[0] = sharedKeyR1
	circuitID := setupResp.CircuitID // Use the CircuitID confirmed/assigned by the entry node
	fmt.Printf("DEBUG: Established key K1 with entry node %s for circuit %s\n", entryNode, circuitID)

	// Step 2: Extend the circuit iteratively (R2, R3, ...)
	// The logic here needs significant changes based on the protocol.
	// We send TypeExtend to R(i-1) containing the NextHopPeerID (Ri) and the client's PublicKey for Ri, encrypted with K(i-1).
	for i := 1; i < len(path); i++ {
		nextNode := path[i]
		// prevNode := path[i-1] // The node we are extending from (R(i-1))

		// Generate client's ephemeral keys for the *next* hop (Ri)
		clientPrivKeyRi, clientPubKeyRiBytes, err := GenerateEphemeralKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral keys for hop %d (%s): %w", i+1, nextNode, err)
		}

		// Encrypt the client's public key for Ri using the shared key with R(i-1)
		encryptedClientPubKeyRi, err := EncryptPayload(sharedKeys[i-1], clientPubKeyRiBytes)
		if err != nil {
			currentStream.Reset()
			return nil, fmt.Errorf("failed to encrypt client pubkey for hop %d (%s): %w", i+1, nextNode, err)
		}

		// Prepare the TypeExtend message to send to R(i-1) via the existing stream
		extendReq := &CircuitSetupMessage{
			Type:          TypeExtend,              // Use protocol constant
			CircuitID:     circuitID,               // Use the established circuit ID
			NextHopPeerID: nextNode,                // Tell R(i-1) who the next hop (Ri) is
			PublicKey:     encryptedClientPubKeyRi, // Encrypted client PubKey for Ri
		}

		// Send the extend request
		if err := WriteGob(currentStream, extendReq); err != nil {
			currentStream.Reset()
			return nil, fmt.Errorf("failed to send extend request for hop %d (%s) via %s: %w", i+1, nextNode, entryNode, err)
		}

		// Receive the extend response (TypeExtended) from R(i-1)
		var extendResp CircuitSetupResponse
		if err := ReadGob(currentStream, &extendResp); err != nil {
			currentStream.Reset()
			return nil, fmt.Errorf("failed to read extend response for hop %d (%s) from %s: %w", i+1, nextNode, entryNode, err)
		}

		// Check response validity
		if extendResp.Type != TypeExtended || extendResp.CircuitID != circuitID {
			currentStream.Reset()
			return nil, fmt.Errorf("received unexpected extend response type (%d) or circuit ID (%s) for hop %d (%s)",
				extendResp.Type, extendResp.CircuitID, i+1, nextNode)
		}
		if extendResp.Status != StatusOK {
			currentStream.Reset()
			errMsg := "extend failed"
			if len(extendResp.PublicKey) > 0 { // Assuming error message might be in PublicKey field
				errMsg = string(extendResp.PublicKey)
			}
			return nil, fmt.Errorf("received error extend response for hop %d (%s): status=%d, msg=%s",
				i+1, nextNode, extendResp.Status, errMsg)
		}
		if len(extendResp.PublicKey) == 0 {
			currentStream.Reset()
			return nil, fmt.Errorf("node %s (hop %d) did not provide encrypted public key", nextNode, i+1)
		}

		// Decrypt the public key of Ri received from R(i-1) using K(i-1)
		relayPubKeyRiBytes, err := DecryptPayload(sharedKeys[i-1], extendResp.PublicKey)
		if err != nil {
			currentStream.Reset()
			return nil, fmt.Errorf("failed to decrypt relay pubkey for hop %d (%s): %w", i+1, nextNode, err)
		}

		// Compute shared key Ki using DeriveSharedKey
		sharedKeyRi, err := DeriveSharedKey(clientPrivKeyRi, relayPubKeyRiBytes)
		if err != nil {
			currentStream.Reset()
			return nil, fmt.Errorf("failed to compute shared secret with node %s (hop %d): %w", nextNode, i+1, err)
		}
		sharedKeys[i] = sharedKeyRi
		fmt.Printf("DEBUG: Successfully established key K%d with hop %d (%s) for circuit %s\n", i+1, i+1, nextNode, circuitID)
	}

	// Circuit built successfully
	circuit := &ClientCircuit{
		ID:        circuitID,
		Path:      path,
		Keys:      sharedKeys,
		EntryNode: entryNode,
		ExitNode:  exitNode,
		CreatedAt: time.Now(),
	}

	// Store the stream in the circuit struct
	circuit.Stream = currentStream

	fmt.Printf("DEBUG: Circuit built successfully: ID=%s, Path=%v\n", circuit.ID, circuit.Path) // Debug log
	return circuit, nil
}

// SendData prepares the onion packet and sends it through the circuit's entry node stream.
func (cc *ClientCircuit) SendData(ctx context.Context, messageType uint, payload []byte, finalDestination peer.ID) error {
	if cc.Stream == nil {
		return fmt.Errorf("circuit %s has no active stream to send data", cc.ID)
	}

	// 1. Create the InnerPayload
	inner := InnerPayload{ // Use type directly from the same package
		FinalRecipient: finalDestination,
		MessageType:    messageType, // TODO: Define proper message types for application data
		Data:           payload,
	}

	// 2. Encode the InnerPayload using gob
	// TODO: Need a proper encoding function (e.g., gob, json, protobuf) for InnerPayload
	// Using json temporarily as placeholder, assuming packet.go might define one later
	innerPayloadBytes, err := json.Marshal(&inner) // Using json for now, consider gob or protobuf
	if err != nil {
		return fmt.Errorf("failed to marshal inner payload for circuit %s: %w", cc.ID, err)
	}
	encodedInnerPayload := innerPayloadBytes // Use the marshalled bytes
	if err != nil {
		return fmt.Errorf("failed to encode inner payload for circuit %s: %w", cc.ID, err)
	}

	// 3. Create the Onion Packet using CreateOnionLayers
	// 3. Create the Onion Packet using CreateOnionLayers
	// Pass the finalDestination as the third argument
	onionPacket, err := CreateOnionLayers(cc.Path, cc.Keys, finalDestination, encodedInnerPayload)
	if err != nil {
		return fmt.Errorf("failed to create onion layers for circuit %s: %w", cc.ID, err)
	}

	// 4. Send the OnionPacket over the stream
	// Use a timeout from context or set a deadline
	// TODO: Use configured stream timeout from CircuitBuilderOptions?
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // Example timeout
	defer cancel()

	deadline, hasDeadline := writeCtx.Deadline()
	if hasDeadline {
		cc.Stream.SetWriteDeadline(deadline)
		defer cc.Stream.SetWriteDeadline(time.Time{}) // Clear deadline afterwards
	}

	if err := WriteGob(cc.Stream, onionPacket); err != nil {
		// Consider resetting the stream on error
		_ = cc.Stream.Reset()
		cc.Stream = nil // Mark stream as potentially unusable
		return fmt.Errorf("failed to write onion packet to stream for circuit %s: %w", cc.ID, err)
	}

	fmt.Printf("DEBUG: Sent data packet via circuit %s to %s (type %d)\n", cc.ID, finalDestination, messageType)
	return nil
}

// Close sends a teardown message to the entry node and closes the stream.
func (cc *ClientCircuit) Close() error {
	if cc.Stream == nil {
		return fmt.Errorf("circuit %s has no active stream to close", cc.ID)
	}

	// Send teardown message
	teardownMsg := &CircuitSetupMessage{
		Type:      TypeTeardown, // Use protocol constant
		CircuitID: cc.ID,
		// Other fields not needed for teardown
	}

	// Set write deadline on the stream for sending the teardown message
	// TODO: Make timeout configurable? Use value from CircuitBuilderOptions?
	cc.Stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := WriteGob(cc.Stream, teardownMsg)
	cc.Stream.SetWriteDeadline(time.Time{}) // Clear deadline

	if err != nil {
		// Log the error but still attempt to close the stream
		fmt.Printf("WARN: Failed to send teardown message for circuit %s: %v. Closing stream anyway.\n", cc.ID, err)
		// Reset might be better than Close if the stream is already broken
		_ = cc.Stream.Reset()
		return fmt.Errorf("failed to send teardown message: %w", err)
	}

	fmt.Printf("DEBUG: Sent teardown message for circuit %s\n", cc.ID)

	// Close the stream gracefully
	err = cc.Stream.Close()
	if err != nil {
		// Log error, maybe reset if close fails?
		fmt.Printf("WARN: Error closing stream for circuit %s after teardown: %v\n", cc.ID, err)
		_ = cc.Stream.Reset() // Attempt reset as fallback
		return fmt.Errorf("error closing stream after teardown: %w", err)
	}

	cc.Stream = nil // Mark stream as closed
	fmt.Printf("DEBUG: Closed stream for circuit %s\n", cc.ID)
	return nil
}
