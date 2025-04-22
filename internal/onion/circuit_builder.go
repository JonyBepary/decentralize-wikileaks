package onion

import (
	"bytes" // Import bytes for gob encoding
	"context"
	"encoding/gob" // Import gob for serialization
	"fmt"          // Import fmt for error formatting
	"log"          // Added for debugging
	"sync"         // Import sync for mutex
	"time"         // Import time

	"github.com/google/uuid" // For generating unique circuit IDs
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	// log "github.com/sirupsen/logrus" // Consider adding logging
)

// CircuitBuilder is responsible for initiating and building onion circuits.
type CircuitBuilder struct {
	host host.Host
	// TODO: Add configuration options (e.g., default path length, timeouts)
}

// ClientCircuit represents an established circuit from the client's perspective.
type ClientCircuit struct {
	ID        string             // Unique identifier for this circuit
	Path      []peer.ID          // Ordered list of peer IDs forming the circuit path
	EntryNode peer.ID            // The first hop in the circuit
	ExitNode  peer.ID            // The final hop (relay) in the circuit
	Keys      [][]byte           // Symmetric keys for each hop (derived via DH)
	Stream    network.Stream     // The libp2p stream to the entry node for setup/teardown/data
	host      host.Host          // Reference to the local host for closing stream
	ctx       context.Context    // Context for managing the circuit's lifecycle
	cancel    context.CancelFunc // Function to cancel the circuit's context
	mu        sync.Mutex         // Mutex to protect concurrent access to stream state
}

// NewCircuitBuilder creates a new CircuitBuilder instance.
func NewCircuitBuilder(h host.Host) (*CircuitBuilder, error) {
	if h == nil {
		return nil, fmt.Errorf("host cannot be nil")
	}
	return &CircuitBuilder{
		host: h,
	}, nil
}

// BuildCircuit attempts to establish an onion circuit through the specified path of relay nodes.
// It uses a telescoping build process, establishing one hop at a time.
func (cb *CircuitBuilder) BuildCircuit(ctx context.Context, path []peer.ID) (*ClientCircuit, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("circuit path cannot be empty")
	}

	circuitID := uuid.NewString()
	log.Printf("[%s] Client: Building circuit %s with path: %v", time.Now().Format(time.RFC3339Nano), circuitID, path) // DEBUG

	entryNode := path[0]
	exitNode := path[len(path)-1]

	// Create a context for this specific circuit build attempt
	buildCtx, cancel := context.WithTimeout(ctx, 60*time.Second) // TODO: Make timeout configurable
	defer cancel()                                               // Ensure cancellation happens if function exits early

	// 1. Connect and open setup stream to the entry node
	log.Printf("[%s] Client: Opening setup stream to entry node %s for circuit %s", time.Now().Format(time.RFC3339Nano), entryNode, circuitID) // DEBUG
	stream, err := cb.host.NewStream(buildCtx, entryNode, protocol.ID(CircuitSetupProtocol))
	if err != nil {
		return nil, fmt.Errorf("failed to open setup stream to entry node %s: %w", entryNode, err)
	}
	log.Printf("[%s] Client: Setup stream opened: %s", time.Now().Format(time.RFC3339Nano), stream.ID()) // DEBUG

	// Defer stream reset/close based on success or failure
	success := false
	defer func() {
		if !success && stream != nil {
			log.Printf("[%s] Client: Resetting stream due to build error for circuit %s", time.Now().Format(time.RFC3339Nano), circuitID) // DEBUG
			_ = stream.Reset()                                                                                                            // Reset on error
		}
	}()

	// --- Handshake Removed ---
	// The byte-level handshake (0x01/0x02) was removed as it caused a mismatch
	// with the relay, which expects the gob message directly.

	// Create encoder and decoder directly on the stream
	// The underlying MockStream or real stream should handle buffering if needed.
	encoder := gob.NewEncoder(stream)
	decoder := gob.NewDecoder(stream)

	keys := make([][]byte, len(path))
	var relayHopPubKeyBytes []byte // To store the public key received from the relay

	// 3. Establish/Extend hop by hop
	for i, hopPeerID := range path {
		log.Printf("[%s] Client: Processing hop %d: %s for circuit %s", time.Now().Format(time.RFC3339Nano), i, hopPeerID, circuitID) // DEBUG

		clientHopPrivKey, clientHopPubKeyBytes, err := GenerateEphemeralKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral key for hop %d (%s): %w", i, hopPeerID, err)
		}

		var nextHopInPath peer.ID
		if i+1 < len(path) {
			nextHopInPath = path[i+1]
		}

		if i == 0 { // First hop: Establish
			establishReq := CircuitSetupMessage{
				Type:          TypeEstablish,
				CircuitID:     circuitID,
				PublicKey:     clientHopPubKeyBytes,
				NextHopPeerID: nextHopInPath, // Tell R1 about R2 if it exists
				// NextNextHopPeerID is not relevant for TypeEstablish
			}

			log.Printf("[%s] Client: Sending Establish request to %s for circuit %s", time.Now().Format(time.RFC3339Nano), hopPeerID, circuitID) // DEBUG
			err = encoder.Encode(&establishReq)
			if err != nil {
				log.Printf("[%s] Client: Error sending Establish request to %s: %v", time.Now().Format(time.RFC3339Nano), hopPeerID, err) // DEBUG
				return nil, fmt.Errorf("failed to send Establish request for hop %d (%s): %w", i, hopPeerID, err)
			}
			// Flush is likely handled by gob encoder or underlying stream; removed explicit flush
			// err = bufWriter.Flush() // Removed
			// if err != nil {
			// 	log.Printf("[%s] Client: Error flushing Establish request to %s: %v", time.Now().Format(time.RFC3339Nano), hopPeerID, err) // DEBUG
			// 	return nil, fmt.Errorf("failed to flush Establish request for hop %d (%s): %w", i, hopPeerID, err)
			// }
			log.Printf("[%s] Client: Sent Establish request to %s", time.Now().Format(time.RFC3339Nano), hopPeerID) // DEBUG

			// Read Established response
			var establishResp CircuitSetupResponse
			log.Printf("[%s] Client: Waiting for Establish response from %s on stream %s (before Decode)", time.Now().Format(time.RFC3339Nano), hopPeerID, stream.ID()) // DEBUG
			err = decoder.Decode(&establishResp)
			if err != nil {
				log.Printf("[%s] Client: Error reading Establish response from %s on stream %s: %v", time.Now().Format(time.RFC3339Nano), hopPeerID, stream.ID(), err) // DEBUG
				return nil, fmt.Errorf("failed to read Establish response for hop %d (%s): %w", i, hopPeerID, err)
			}
			log.Printf("[%s] Client: Successfully decoded Establish response from %s on stream %s (Status: %d)", time.Now().Format(time.RFC3339Nano), hopPeerID, stream.ID(), establishResp.Status) // DEBUG

			if establishResp.Status != StatusOK || establishResp.Type != TypeEstablished {
				return nil, fmt.Errorf("entry node %s rejected circuit setup: status %d, type %d", hopPeerID, establishResp.Status, establishResp.Type)
			}
			if establishResp.CircuitID != circuitID {
				return nil, fmt.Errorf("entry node %s responded with wrong circuit ID: expected %s, got %s", hopPeerID, circuitID, establishResp.CircuitID)
			}
			if len(establishResp.PublicKey) == 0 {
				return nil, fmt.Errorf("entry node %s did not provide public key", hopPeerID)
			}
			relayHopPubKeyBytes = establishResp.PublicKey

		} else { // Subsequent hops: Extend
			// Determine the hop *after* the current target hop (hopPeerID)
			var nextNextHopInPath peer.ID
			if i+1 < len(path) {
				nextNextHopInPath = path[i+1]
			}

			extendReq := CircuitSetupMessage{
				Type:              TypeExtend,
				CircuitID:         circuitID,
				PublicKey:         clientHopPubKeyBytes,
				NextHopPeerID:     hopPeerID,         // Target of this extension step
				NextNextHopPeerID: nextNextHopInPath, // Tell the previous hop about the one after this target [NEW]
			}

			log.Printf("[%s] Client: Sending Extend request targeting %s (next: %s) via entry node for circuit %s", time.Now().Format(time.RFC3339Nano), hopPeerID, nextNextHopInPath, circuitID) // DEBUG
			log.Printf("[%s] Client: Extend request NextHopPeerID being sent: [%s]", time.Now().Format(time.RFC3339Nano), extendReq.NextHopPeerID.String())                                       // MORE DEBUG
			log.Printf("[%s] Client: Extend request NextNextHopPeerID being sent: [%s]", time.Now().Format(time.RFC3339Nano), extendReq.NextNextHopPeerID.String())                               // MORE DEBUG
			err = encoder.Encode(&extendReq)
			if err != nil {
				log.Printf("[%s] Client: Error sending Extend request targeting %s: %v", time.Now().Format(time.RFC3339Nano), hopPeerID, err) // DEBUG
				return nil, fmt.Errorf("failed to send Extend request for hop %d (%s): %w", i, hopPeerID, err)
			}
			// Flush is likely handled by gob encoder or underlying stream; removed explicit flush
			// err = bufWriter.Flush() // Removed
			// if err != nil {
			// 	log.Printf("[%s] Client: Error flushing Extend request targeting %s: %v", time.Now().Format(time.RFC3339Nano), hopPeerID, err) // DEBUG
			// 	return nil, fmt.Errorf("failed to flush Extend request for hop %d (%s): %w", i, hopPeerID, err)
			// }
			log.Printf("[%s] Client: Sent Extend request targeting %s", time.Now().Format(time.RFC3339Nano), hopPeerID) // DEBUG

			// Read Extended response
			var extendedResp CircuitSetupResponse
			log.Printf("[%s] Client: Waiting for Extended response for hop %s on stream %s (before Decode)", time.Now().Format(time.RFC3339Nano), hopPeerID, stream.ID()) // DEBUG
			err = decoder.Decode(&extendedResp)
			if err != nil {
				log.Printf("[%s] Client: Error reading Extended response for hop %s on stream %s: %v", time.Now().Format(time.RFC3339Nano), hopPeerID, stream.ID(), err) // DEBUG
				return nil, fmt.Errorf("failed to read Extended response for hop %d (%s): %w", i, hopPeerID, err)
			}
			log.Printf("[%s] Client: Successfully decoded Extended response for hop %s on stream %s (Status: %d)", time.Now().Format(time.RFC3339Nano), hopPeerID, stream.ID(), extendedResp.Status) // DEBUG

			if extendedResp.Status != StatusOK || extendedResp.Type != TypeExtended {
				return nil, fmt.Errorf("relay node %s rejected circuit extension: status %d, type %d", hopPeerID, extendedResp.Status, extendedResp.Type)
			}
			if extendedResp.CircuitID != circuitID {
				return nil, fmt.Errorf("relay node %s responded with wrong circuit ID for extension: expected %s, got %s", hopPeerID, circuitID, extendedResp.CircuitID)
			}
			if len(extendedResp.PublicKey) == 0 {
				return nil, fmt.Errorf("relay node %s did not provide public key in Extended response", hopPeerID)
			}
			relayHopPubKeyBytes = extendedResp.PublicKey
		}

		// Derive shared key for this hop
		sharedKey, err := DeriveSharedKey(clientHopPrivKey, relayHopPubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to derive shared key for hop %d (%s): %w", i, hopPeerID, err)
		}
		keys[i] = sharedKey
		log.Printf("[%s] Client: Derived shared key for hop %d (%s)", time.Now().Format(time.RFC3339Nano), i, hopPeerID) // DEBUG
	}

	// If loop completed successfully for all hops
	success = true // Mark as success so stream isn't reset by defer
	circuitCtx, circuitCancel := context.WithCancel(ctx)
	circuit := &ClientCircuit{
		ID:        circuitID,
		Path:      path,
		EntryNode: entryNode,
		ExitNode:  exitNode,
		Keys:      keys,
		Stream:    stream, // Keep the stream open
		host:      cb.host,
		ctx:       circuitCtx,
		cancel:    circuitCancel,
	}
	log.Printf("[%s] Client: Circuit %s successfully built (%d hops)", time.Now().Format(time.RFC3339Nano), circuitID, len(path)) // DEBUG
	return circuit, nil
}

// Close tears down the circuit by sending a teardown message to the entry node
// and closing the underlying libp2p stream.
// Close tears down the circuit by sending a teardown message to the entry node
// over a dedicated teardown stream and then closing the main circuit stream.
func (cc *ClientCircuit) Close() error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.Stream == nil {
		log.Printf("[%s] Circuit %s: Close called on already closed or nil stream", time.Now().Format(time.RFC3339Nano), cc.ID) // DEBUG log
		return nil                                                                                                              // Already closed or wasn't properly initialized
	}

	log.Printf("[%s] Circuit %s: Closing circuit", time.Now().Format(time.RFC3339Nano), cc.ID) // DEBUG log

	// 1. Send Teardown message over a separate stream
	teardownMsg := CircuitSetupMessage{ // Use CircuitSetupMessage for now
		Type:      TypeTeardown,
		CircuitID: cc.ID,
	}

	// Use a short timeout context for the teardown attempt
	tdCtx, tdCancel := context.WithTimeout(cc.ctx, 5*time.Second)
	defer tdCancel()

	log.Printf("[%s] Circuit %s: Opening teardown stream to %s", time.Now().Format(time.RFC3339Nano), cc.ID, cc.EntryNode) // DEBUG log
	teardownStream, err := cc.host.NewStream(tdCtx, cc.EntryNode, protocol.ID(CircuitTeardownProtocol))
	if err != nil {
		// Log error but proceed with closing the main stream anyway
		log.Printf("[%s] Circuit %s: Failed to open teardown stream to %s: %v. Proceeding to close main stream.", time.Now().Format(time.RFC3339Nano), cc.ID, cc.EntryNode, err) // DEBUG log
	} else {
		log.Printf("[%s] Circuit %s: Teardown stream opened: %s", time.Now().Format(time.RFC3339Nano), cc.ID, teardownStream.ID()) // DEBUG log
		err = WriteGob(teardownStream, &teardownMsg)
		if err != nil {
			// Log error but proceed with closing streams
			log.Printf("[%s] Circuit %s: Failed to send teardown message via dedicated stream: %v. Resetting teardown stream.", time.Now().Format(time.RFC3339Nano), cc.ID, err) // DEBUG log
			_ = teardownStream.Reset()
		} else {
			log.Printf("[%s] Circuit %s: Teardown message sent via dedicated stream.", time.Now().Format(time.RFC3339Nano), cc.ID) // DEBUG log
		}
		// Close the teardown stream immediately after sending (or attempting to send)
		_ = teardownStream.Close()
		log.Printf("[%s] Circuit %s: Teardown stream closed.", time.Now().Format(time.RFC3339Nano), cc.ID) // DEBUG log
	}

	// 2. Close the original main circuit stream
	log.Printf("[%s] Circuit %s: Closing main stream %s", time.Now().Format(time.RFC3339Nano), cc.ID, cc.Stream.ID()) // DEBUG log
	if closeErr := cc.Stream.Close(); closeErr != nil {
		log.Printf("[%s] Circuit %s: Error closing main stream (Resetting instead): %v", time.Now().Format(time.RFC3339Nano), cc.ID, closeErr) // DEBUG log
		_ = cc.Stream.Reset()
	} else {
		log.Printf("[%s] Circuit %s: Main stream closed gracefully.", time.Now().Format(time.RFC3339Nano), cc.ID) // DEBUG log
	}
	cc.Stream = nil // Mark main stream as closed locally

	// 3. Cancel the circuit's context
	if cc.cancel != nil {
		cc.cancel()
	}

	log.Printf("[%s] Circuit %s: Circuit closed function finished.", time.Now().Format(time.RFC3339Nano), cc.ID) // DEBUG log
	return nil                                                                                                   // Return nil even if teardown send failed, as streams are closed/reset
}

// SendData wraps the payload in onion layers and sends it over a new data stream
// via the established circuit to the entry node.
// The destination peer ID is used by CreateOnionLayers to structure the reply info
// if needed, but the actual routing is dictated by the layered encryption.
func (cc *ClientCircuit) SendData(ctx context.Context, destination peer.ID, payload []byte) error {
	cc.mu.Lock() // Lock to prevent closing the circuit while sending
	if cc.Stream == nil {
		cc.mu.Unlock()
		return fmt.Errorf("circuit %s is closed, cannot send data", cc.ID)
	}
	// We copy necessary fields under lock to use them after unlock
	circuitID := cc.ID
	entryNode := cc.EntryNode
	path := cc.Path
	keys := cc.Keys
	host := cc.host
	cc.mu.Unlock() // Unlock early to allow concurrent Sends or Close attempts

	log.Printf("[%s] Circuit %s: Preparing to send data (%d bytes) via entry %s", time.Now().Format(time.RFC3339Nano), circuitID, len(payload), entryNode) // DEBUG log

	// 1. Create InnerPayload
	inner := InnerPayload{
		// MessageType: MessageTypeData, // Example if we add types
		// FinalRecipient: destination, // Could be added if needed by exit node logic beyond routing
		Data: payload,
	}

	// 2. Serialize InnerPayload using gob
	var innerPayloadBuf bytes.Buffer
	if err := gob.NewEncoder(&innerPayloadBuf).Encode(&inner); err != nil {
		return fmt.Errorf("failed to serialize inner payload for circuit %s: %w", circuitID, err)
	}
	serializedInnerPayload := innerPayloadBuf.Bytes()
	log.Printf("[%s] Circuit %s: Inner payload serialized (%d bytes)", time.Now().Format(time.RFC3339Nano), circuitID, len(serializedInnerPayload)) // DEBUG log

	// 3. Wrap in onion layers
	// CreateOnionLayers handles the layering and encryption using the circuit keys.
	encryptedPayloadBytes, err := CreateOnionLayers(path, keys, destination, serializedInnerPayload)
	if err != nil {
		return fmt.Errorf("failed to create onion layers for circuit %s: %w", circuitID, err)
	}
	log.Printf("[%s] Circuit %s: Onion layers created (%d bytes total)", time.Now().Format(time.RFC3339Nano), circuitID, len(encryptedPayloadBytes)) // DEBUG log

	// 4. Construct the OnionPacket to send to the entry node
	// The HopInfo here tells the *entry node* where to send the packet next (R2)
	var nextHopForEntry peer.ID
	if len(path) > 1 {
		nextHopForEntry = path[1]
	} else {
		// This shouldn't happen for multi-hop SendData, but handle defensively.
		// If it's a single-hop circuit, the entry *is* the exit.
		// The HopInfo might be less critical, maybe point to self or destination?
		// Let's assume CreateOnionLayers handled this appropriately,
		// and the entry node's decryption will yield InnerPayload.
		// For now, leave it potentially empty, relying on entry node logic.
		log.Printf("[%s] Circuit %s: Warning - single hop circuit detected in SendData?", time.Now().Format(time.RFC3339Nano), circuitID) // DEBUG log
		nextHopForEntry = entryNode                                                                                                       // Point to self? or destination? Let's stick to entry node for now.

	}

	packetToSend := &OnionPacket{
		CircuitID: circuitID,
		HopInfo: HopInfo{
			NextPeer: nextHopForEntry, // Tell R1 where to send after decryption
		},
		EncryptedPayload: encryptedPayloadBytes,
	}

	// 5. Open a *new* stream to the entry node using the RelayProtocol
	log.Printf("[%s] Circuit %s: Opening data stream to entry node %s", time.Now().Format(time.RFC3339Nano), circuitID, entryNode) // DEBUG log

	// Use a separate context for the data stream attempt, derived from the input ctx
	streamCtx, streamCancel := context.WithTimeout(ctx, 15*time.Second) // Timeout for stream opening + sending
	defer streamCancel()

	dataStream, err := host.NewStream(streamCtx, entryNode, protocol.ID(RelayProtocol))
	if err != nil {
		// If opening the data stream fails, the circuit might still be usable for setup/teardown.
		return fmt.Errorf("failed to open data stream for circuit %s: %w", circuitID, err)
	}
	defer dataStream.Close()                                                                                               // Ensure data stream is closed after sending
	log.Printf("[%s] Circuit %s: Data stream opened: %s", time.Now().Format(time.RFC3339Nano), circuitID, dataStream.ID()) // DEBUG log

	// 6. Send the OnionPacket over the data stream
	log.Printf("[%s] Circuit %s: Sending data packet over data stream %s", time.Now().Format(time.RFC3339Nano), circuitID, dataStream.ID()) // DEBUG log

	// Set write deadline based on context or default
	deadline, hasDeadline := streamCtx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(10 * time.Second) // Default send timeout if context has no deadline
	}
	if err := dataStream.SetWriteDeadline(deadline); err != nil {
		log.Printf("[%s] Circuit %s: Warning - Failed to set write deadline for data stream: %v", time.Now().Format(time.RFC3339Nano), circuitID, err) // DEBUG log
	}
	// No need to defer clearing deadline, Close() handles it.

	err = WriteGob(dataStream, packetToSend)
	if err != nil {
		// If sending fails on the data stream, reset it. The main circuit might still be okay.
		log.Printf("[%s] Circuit %s: Failed to send data packet over data stream %s: %v. Resetting data stream.", time.Now().Format(time.RFC3339Nano), circuitID, dataStream.ID(), err) // DEBUG log
		_ = dataStream.Reset()                                                                                                                                                          // Reset data stream on error
		return fmt.Errorf("failed to send data packet over circuit %s data stream: %w", circuitID, err)
	}

	log.Printf("[%s] Circuit %s: Data packet sent successfully over data stream %s", time.Now().Format(time.RFC3339Nano), circuitID, dataStream.ID()) // DEBUG log
	return nil
}

// Context returns the context associated with the circuit's lifetime.
func (cc *ClientCircuit) Context() context.Context {
	return cc.ctx
}
