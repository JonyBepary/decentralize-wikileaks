// filepath: /home/jony/Project/decentralize-wikileaks/internal/onion/relay.go
package onion

import (
	"context"
	"fmt"
	"sync"
	"time"

	// "github.com/google/uuid" // Removed - Using string for CircuitID now
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	log "github.com/sirupsen/logrus"
)

// Circuit represents the state of one circuit passing through this relay node.
type Circuit struct {
	ID         string         // Unique identifier for this circuit (Using string now)
	PrevPeer   peer.ID        // The peer we received the setup/data from for this circuit hop
	NextPeer   peer.ID        // The peer we should forward data to for this circuit hop
	SharedKey  []byte         // Symmetric key shared with the circuit initiator for this hop
	IsExitNode bool           // Is this the last relay in the circuit?
	LastActive time.Time      // Timestamp of the last activity on this circuit
	Stream     network.Stream // The stream to the *next* hop (if not exit node)
	streamMu   sync.Mutex     // Mutex for accessing the Stream field
	// TODO: Add rate limiting, statistics, etc.
}

// Relay manages onion routing services for a libp2p host.
type Relay struct {
	host       host.Host
	circuits   map[string]*Circuit // Map of active circuits passing through this node (Using string key now)
	circuitsMu sync.RWMutex        // Mutex for accessing the circuits map
	ctx        context.Context
	cancel     context.CancelFunc
	logger     *log.Entry
}

// NewRelay creates and initializes a new Relay service.
func NewRelay(ctx context.Context, h host.Host) *Relay {
	childCtx, cancel := context.WithCancel(ctx)
	relay := &Relay{
		host:     h,
		circuits: make(map[string]*Circuit), // Using string key now
		ctx:      childCtx,
		cancel:   cancel,
		logger: log.WithFields(log.Fields{
			"module": "onion-relay",
			"node":   h.ID().ShortString(),
		}),
	}

	// Register stream handlers
	h.SetStreamHandler(CircuitSetupProtocol, relay.handleCircuitSetup)
	h.SetStreamHandler(RelayProtocol, relay.handleRelayStream)
	h.SetStreamHandler(CircuitTeardownProtocol, relay.handleCircuitTeardown) // Keep explicit teardown

	relay.logger.Info("Relay service started, listening for setup and relay protocols")

	// Start background task for cleaning up stale circuits
	go relay.cleanupStaleCircuitsLoop(1 * time.Minute) // Check every minute

	return relay
}

// Stop shuts down the Relay service.
func (r *Relay) Stop() {
	r.logger.Info("Stopping Relay service...")
	r.cancel() // Signal background tasks to stop
	// Unregister stream handlers
	r.host.RemoveStreamHandler(CircuitSetupProtocol)
	r.host.RemoveStreamHandler(RelayProtocol)
	r.host.RemoveStreamHandler(CircuitTeardownProtocol)

	// Close all active circuit streams
	r.circuitsMu.Lock()
	defer r.circuitsMu.Unlock()
	for id, circuit := range r.circuits {
		if circuit.Stream != nil {
			circuit.Stream.Close()
		}
		delete(r.circuits, id) // Remove from map
	}
	r.logger.Info("Relay service stopped")
}

// --- Stream Handlers ---

// handleRelayStream handles incoming data streams for relaying onion packets.
func (r *Relay) handleRelayStream(s network.Stream) {
	remotePeer := s.Conn().RemotePeer() // Changed from s.Peer()
	r.logger.Debugf("Received relay stream from %s", remotePeer.ShortString())
	defer s.Close()

	// Read the OnionPacket
	var onion OnionPacket
	err := ReadGob(s, &onion)
	if err != nil {
		r.logger.Errorf("Failed to read onion packet from %s: %v", remotePeer.ShortString(), err)
		return
	}

	// Find the corresponding circuit
	// Use the CircuitID string from the packet
	r.circuitsMu.RLock()
	circuit, ok := r.circuits[onion.CircuitID] // Use string CircuitID from packet
	r.circuitsMu.RUnlock()

	if !ok {
		r.logger.Warnf("Received relay data for unknown circuit ID %s from %s", onion.CircuitID, remotePeer.ShortString())
		// TODO: Send back an error? Or just drop?
		return
	}

	// Update last active time
	circuit.LastActive = time.Now()

	// Decrypt the payload layer
	// Assuming DecryptPayload exists and works
	decryptedPayload, err := DecryptPayload(circuit.SharedKey, onion.EncryptedPayload)
	if err != nil {
		r.logger.Errorf("Failed to decrypt payload for circuit %s from %s: %v", onion.CircuitID, remotePeer.ShortString(), err)
		// TODO: Teardown circuit? Send error back?
		return
	}

	if circuit.IsExitNode {
		// --- Exit Node Logic ---
		r.logger.Debugf("Circuit %s: Reached exit node. Handling inner payload.", onion.CircuitID)
		// Attempt to decode as the final InnerPayload
		// Assuming DecodeInnerPayload returns (*InnerPayload, error)
		innerPayload, err := DecodeInnerPayload(decryptedPayload) // Assign both return values
		if err != nil {
			r.logger.Errorf("Circuit %s: Failed to decode inner payload at exit node: %v", onion.CircuitID, err)
			return
		}

		// Process the inner payload based on its type
		// Use MessageType and FinalRecipient fields from packet.InnerPayload
		r.logger.Infof("Circuit %s: Received InnerPayload: Type=%d, Recipient=%s, DataLen=%d",
			onion.CircuitID, innerPayload.MessageType, innerPayload.FinalRecipient.ShortString(), len(innerPayload.Data))

		switch innerPayload.MessageType { // Use MessageType field
		case MessageTypePublishDocument: // Use updated constant name
			r.logger.Info("-> Exit Node: Handling Publish Document request (placeholder)")
			// Placeholder: Store blocks, announce CID via DHT/PubSub, etc.
		// Need to interact with other modules (core, p2p) here.
		case MessageTypeRequestBlock: // Use updated constant name
			r.logger.Info("-> Exit Node: Handling Block Request (placeholder)")
		// Placeholder: Fetch block from storage, send back via reply circuit/direct connection?
		case MessageTypeAnnouncement: // Use updated constant name
			r.logger.Info("-> Exit Node: Handling Announcement (placeholder)")
		// Placeholder: Process announcement (e.g., new content available)
		case MessageTypeError: // Use updated constant name
			r.logger.Warn("-> Exit Node: Received Error message in inner payload")
		// Placeholder: Log or handle error reported by another node
		default:
			r.logger.Warnf("-> Exit Node: Received unknown inner payload type: %d", innerPayload.MessageType) // Use MessageType field
		}
		// Exit node processing ends here for this packet.

	} else {
		// --- Intermediate Relay Logic ---
		r.logger.Debugf("Circuit %s: Intermediate node. Forwarding payload.", onion.CircuitID)
		// Expect LayeredPayload structure
		// Assuming DecodeLayeredPayload returns (*LayeredPayload, error) - needs fix in packet.go if not
		layeredPayload, err := DecodeLayeredPayload(decryptedPayload) // Assign both return values
		if err != nil {
			// This should not happen if CreateOnionLayers and decryption work correctly
			r.logger.Errorf("Circuit %s: Failed to decode LayeredPayload at intermediate node: %v", onion.CircuitID, err)
			return
		}

		// Ensure the decoded NextHop matches the circuit's NextPeer
		// Assuming LayeredPayload has NextHop (peer.ID) field - needs fix in packet.go if not
		if layeredPayload.NextHop != circuit.NextPeer {
			r.logger.Errorf("Circuit %s: Mismatch in expected next hop (%s) and decoded next hop (%s)",
				onion.CircuitID, circuit.NextPeer.ShortString(), layeredPayload.NextHop.ShortString())
			// TODO: Teardown circuit? Security issue?
			return
		}

		// Forward the inner encrypted payload (layeredPayload.Payload) to the next hop
		nextStream, err := r.getOrCreateRelayStream(circuit)
		if err != nil {
			r.logger.Errorf("Circuit %s: Failed to get stream to next hop %s: %v", onion.CircuitID, circuit.NextPeer.ShortString(), err)
			// TODO: Teardown circuit?
			return
		}

		// Prepare the onion packet for the next hop (same CircuitID, inner encrypted payload)
		// Assuming OnionPacket has CircuitID and EncryptedPayload fields - needs fix in packet.go if not
		// Assuming LayeredPayload has Payload ([]byte) field - needs fix in packet.go if not
		forwardOnion := OnionPacket{
			CircuitID:        onion.CircuitID,
			EncryptedPayload: layeredPayload.Payload, // Forward the already encrypted inner payload
		}

		err = WriteGob(nextStream, &forwardOnion)
		if err != nil {
			// If forwarding fails, we might need to reset the stream or tear down
			r.logger.Errorf("Circuit %s: Failed to forward onion packet to %s: %v", onion.CircuitID, circuit.NextPeer.ShortString(), err)
			circuit.streamMu.Lock()
			if circuit.Stream != nil {
				circuit.Stream.Reset() // Reset the stream on error
				circuit.Stream = nil
			}
			circuit.streamMu.Unlock()
			// TODO: Teardown circuit?
			return
		}
		r.logger.Debugf("Circuit %s: Forwarded packet to %s", onion.CircuitID, circuit.NextPeer.ShortString())
	}
}

// getOrCreateRelayStream gets the existing stream to the next hop or creates one.
func (r *Relay) getOrCreateRelayStream(circuit *Circuit) (network.Stream, error) {
	circuit.streamMu.Lock()
	defer circuit.streamMu.Unlock()

	if circuit.Stream != nil {
		// TODO: Check if stream is still valid? Maybe add a health check?
		return circuit.Stream, nil
	}

	r.logger.Debugf("Circuit %s: Creating new relay stream to %s", circuit.ID, circuit.NextPeer.ShortString()) // circuit.ID is string
	s, err := r.host.NewStream(r.ctx, circuit.NextPeer, RelayProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to open relay stream: %w", err)
	}
	circuit.Stream = s
	return s, nil
}

// handleCircuitSetup handles incoming requests to set up or extend a circuit.
func (r *Relay) handleCircuitSetup(s network.Stream) {
	remotePeer := s.Conn().RemotePeer() // Changed from s.Peer()
	r.logger.Debugf("Received circuit setup stream from %s", remotePeer.ShortString())
	defer s.Close()

	// Read the setup message
	var setupMsg CircuitSetupMessage
	err := ReadGob(s, &setupMsg)
	if err != nil {
		r.logger.Errorf("Failed to read setup message from %s: %v", remotePeer.ShortString(), err)
		return
	}

	switch setupMsg.Type {
	case TypeEstablish: // Use updated constant name
		// --- Handle Initial Circuit Setup Request (Client -> R1) ---
		// Assuming setupMsg.CircuitID is the correct field name (string)
		r.logger.Infof("Handling initial setup request from %s (CircuitID: %s)", remotePeer.ShortString(), setupMsg.CircuitID)

		clientPubKeyBytes := setupMsg.PublicKey // Use PublicKey field
		if len(clientPubKeyBytes) == 0 {        // Check if empty instead of size
			r.logger.Errorf("Received empty public key from %s", remotePeer.ShortString())
			r.sendSetupError(s, setupMsg.CircuitID, "Received empty public key")
			return
			// return // Removed duplicate return
		}
		// No need to copy to fixed-size array anymore
		// var clientPubKey [KeySize]byte
		// copy(clientPubKey[:], clientPubKeyBytes)

		// Generate relay's ephemeral key pair for this circuit hop
		// Assuming GenerateEphemeralKeyPair returns ([]byte, []byte, error)
		relayPrivKeyBytes, relayPubKeyBytes, err := GenerateEphemeralKeyPair()
		if err != nil {
			r.logger.Errorf("Failed to generate ephemeral key pair for setup with %s: %v", remotePeer.ShortString(), err)
			r.sendSetupError(s, setupMsg.CircuitID, "Internal server error") // Pass CircuitID
			return
		}

		// Calculate shared secret
		// Assuming DeriveSharedKey takes two []byte keys
		sharedSecret, err := DeriveSharedKey(relayPrivKeyBytes, clientPubKeyBytes)
		if err != nil {
			r.logger.Errorf("Failed to derive shared key with %s: %v", remotePeer.ShortString(), err)
			r.sendSetupError(s, setupMsg.CircuitID, "Key exchange failed")
			return
		}

		// Use the CircuitID provided by the client (string)
		circuitID := setupMsg.CircuitID

		// Create and store circuit state (initially marked as exit node until extended)
		circuit := &Circuit{
			ID:         circuitID, // string ID
			PrevPeer:   remotePeer,
			NextPeer:   "", // No next peer initially
			SharedKey:  sharedSecret,
			IsExitNode: true, // Assume exit node until extended
			LastActive: time.Now(),
		}

		r.circuitsMu.Lock()
		// Check for collision
		if _, exists := r.circuits[circuitID]; exists {
			r.circuitsMu.Unlock()
			r.logger.Errorf("Circuit ID collision for %s", circuitID)
			r.sendSetupError(s, circuitID, "Internal server error (ID collision)")
			return
		}
		r.circuits[circuitID] = circuit
		r.circuitsMu.Unlock()

		r.logger.Infof("Circuit %s: Established with initiator %s (Key derived)", circuitID, remotePeer.ShortString())

		// Send response (Relay PubKey)
		// Assuming CircuitSetupResponse has CircuitID (string)
		respMsg := CircuitSetupResponse{
			Type:      TypeEstablished, // Use updated constant name
			CircuitID: circuitID,
			Status:    StatusOK,
			PublicKey: relayPubKeyBytes, // Use PublicKey field
		}
		err = WriteGob(s, &respMsg)
		if err != nil {
			r.logger.Errorf("Circuit %s: Failed to send setup response to %s: %v", circuitID, remotePeer.ShortString(), err)
			// Best effort, initiator might timeout. Clean up circuit state?
			r.teardownCircuit(circuitID) // Clean up if we can't even send the response
		}

	case TypeExtend: // Use updated constant name
		// --- Handle Circuit Extension Request (Client -> R(i-1) -> Ri) ---
		// This node is R(i-1) receiving the request to extend to Ri

		// Assuming setupMsg.CircuitID and setupMsg.NextHopPeerID are correct fields (string, peer.ID)
		circuitID := setupMsg.CircuitID
		nextHopPeerID := setupMsg.NextHopPeerID
		clientPubKeyForNextHop := setupMsg.PublicKey

		r.logger.Infof("Handling extend request for circuit %s from %s to %s", circuitID, remotePeer.ShortString(), nextHopPeerID.ShortString())

		// 1. Retrieve the circuit state using the CircuitID (string).
		r.circuitsMu.RLock()
		circuitPrev, ok := r.circuits[circuitID]
		r.circuitsMu.RUnlock()
		if !ok {
			r.logger.Errorf("Circuit %s: Received extend request for unknown circuit", circuitID)
			r.sendSetupError(s, circuitID, "Unknown circuit for extension")
			return
		}

		// Security Check: Ensure the request comes from the expected previous peer
		if circuitPrev.PrevPeer != remotePeer {
			r.logger.Errorf("Circuit %s: Unauthorized extend request from %s (expected %s)", circuitID, remotePeer.ShortString(), circuitPrev.PrevPeer.ShortString())
			r.sendSetupError(s, circuitID, "Unauthorized extend request")
			return
		}

		// Security Check: Ensure this is not already extended
		if !circuitPrev.IsExitNode {
			r.logger.Errorf("Circuit %s: Received extend request for already extended circuit", circuitID)
			r.sendSetupError(s, circuitID, "Circuit already extended")
			return
		}

		// 2. Act as a proxy: Open a *new* setup stream to `nextHopPeerID` (Ri).
		nextHopCtx, cancel := context.WithTimeout(r.ctx, 15*time.Second) // Add timeout
		defer cancel()
		nextHopStream, err := r.host.NewStream(nextHopCtx, nextHopPeerID, CircuitSetupProtocol)
		if err != nil {
			r.logger.Errorf("Circuit %s: Failed to open setup stream to next hop %s: %v", circuitID, nextHopPeerID.ShortString(), err)
			r.sendSetupError(s, circuitID, "Failed to connect to next hop")
			return
		}
		defer nextHopStream.Close() // Close stream to Ri when done

		//  3. Send a `TypeEstablish` request to Ri using `clientPubKeyForNextHop`.
		//     Crucially, use the *same CircuitID* so Ri knows it belongs to this chain.
		//     Assuming CircuitSetupMessage has CircuitID (string)
		setupMsgForNextHop := CircuitSetupMessage{
			Type:      TypeEstablish,
			CircuitID: circuitID, // Use the same CircuitID
			PublicKey: clientPubKeyForNextHop,
		}
		err = WriteGob(nextHopStream, &setupMsgForNextHop)
		if err != nil {
			r.logger.Errorf("Circuit %s: Failed to send setup request to next hop %s: %v", circuitID, nextHopPeerID.ShortString(), err)
			r.sendSetupError(s, circuitID, "Failed to send request to next hop")
			return
		}

		//  4. Receive the `TypeEstablished` response from Ri.
		//     Assuming CircuitSetupResponse has CircuitID (string)
		var respFromNextHop CircuitSetupResponse
		err = ReadGob(nextHopStream, &respFromNextHop)
		if err != nil {
			r.logger.Errorf("Circuit %s: Failed to receive setup response from next hop %s: %v", circuitID, nextHopPeerID.ShortString(), err)
			r.sendSetupError(s, circuitID, "No response from next hop")
			return
		}

		// 5. Check Ri's response.
		if respFromNextHop.Status != StatusOK || respFromNextHop.CircuitID != circuitID || respFromNextHop.Type != TypeEstablished {
			errMsg := fmt.Sprintf("Next hop %s failed setup: Status=%d, Type=%d, CircuitID=%s", nextHopPeerID.ShortString(), respFromNextHop.Status, respFromNextHop.Type, respFromNextHop.CircuitID)
			r.logger.Warnf("Circuit %s: %s", circuitID, errMsg)
			// Forward the error status, but don't necessarily forward Ri's public key in this case.
			// Keep the original error message simple for the client.
			r.sendSetupError(s, circuitID, "Next hop failed setup")
			return
		}
		riPubKeyBytes := respFromNextHop.PublicKey
		if len(riPubKeyBytes) == 0 {
			r.logger.Warnf("Circuit %s: Next hop %s sent empty public key", circuitID, nextHopPeerID.ShortString())
			r.sendSetupError(s, circuitID, "Next hop sent invalid key")
			return
		}

		// 6. Update *our* circuit state (`circuitPrev`): Mark as not exit, set NextPeer.
		r.circuitsMu.Lock()
		// Re-check if circuit still exists (might have been torn down concurrently)
		if currentCircuit, exists := r.circuits[circuitID]; exists && currentCircuit == circuitPrev {
			currentCircuit.IsExitNode = false
			currentCircuit.NextPeer = nextHopPeerID
			currentCircuit.LastActive = time.Now()
			r.logger.Infof("Circuit %s: Extended via %s to next hop %s", circuitID, remotePeer.ShortString(), nextHopPeerID.ShortString())
		} else {
			r.circuitsMu.Unlock()
			r.logger.Warnf("Circuit %s: Disappeared during extension process", circuitID)
			// Don't send error back, client will likely timeout or receive error from previous hop
			return
		}
		r.circuitsMu.Unlock()

		//  7. Send the `TypeExtended` response back to the client/previous hop via stream `s`.
		//     The payload is Ri's public key.
		//     Assuming CircuitSetupResponse has CircuitID (string)
		finalResp := CircuitSetupResponse{
			Type:      TypeExtended, // Use updated constant name
			CircuitID: circuitID,
			Status:    StatusOK,
			PublicKey: riPubKeyBytes, // Send Ri's public key back
		}
		err = WriteGob(s, &finalResp)
		if err != nil {
			r.logger.Errorf("Circuit %s: Failed to send extend response back to %s: %v", circuitID, remotePeer.ShortString(), err)
			// If we fail here, the circuit might be left in an inconsistent state.
			// Teardown might be appropriate.
			r.teardownCircuit(circuitID)
		}

	default:
		r.logger.Warnf("Received unknown setup message type %d from %s", setupMsg.Type, remotePeer.ShortString())
		// Assuming setupMsg.CircuitID exists and is string
		r.sendSetupError(s, setupMsg.CircuitID, "Unknown message type")
	}
}

// sendSetupError sends a generic error response during circuit setup.
func (r *Relay) sendSetupError(s network.Stream, circuitID string, errMsg string) { // Changed circuitID type to string
	// Assuming CircuitSetupResponse has CircuitID (string)
	resp := CircuitSetupResponse{
		// Type: Type?, // Maybe add an Error type? For now, just use StatusError.
		CircuitID: circuitID,
		Status:    StatusError,
		PublicKey: []byte(errMsg), // Send error message in PublicKey field for simplicity
	}
	err := WriteGob(s, &resp)
	if err != nil {
		r.logger.Errorf("Circuit %s: Failed to send error response ('%s') to %s: %v", circuitID, errMsg, s.Conn().RemotePeer().ShortString(), err) // Use Conn().RemotePeer()
	}
}

// handleCircuitTeardown handles requests to explicitly tear down a circuit.
func (r *Relay) handleCircuitTeardown(s network.Stream) {
	remotePeer := s.Conn().RemotePeer() // Changed from s.Peer()
	r.logger.Debugf("Received circuit teardown stream from %s", remotePeer.ShortString())
	defer s.Close()

	// Assuming CircuitTeardownMessage has CircuitID (string)
	var teardownMsg CircuitTeardownMessage
	err := ReadGob(s, &teardownMsg)
	if err != nil {
		r.logger.Errorf("Failed to read teardown message from %s: %v", remotePeer.ShortString(), err)
		return
	}

	r.logger.Infof("Circuit %s: Received teardown request from %s: %s", teardownMsg.CircuitID, remotePeer.ShortString(), teardownMsg.Reason)

	// Find the circuit using string ID
	r.circuitsMu.RLock()
	circuit, ok := r.circuits[teardownMsg.CircuitID]
	r.circuitsMu.RUnlock()

	if !ok {
		r.logger.Warnf("Circuit %s: Teardown request for unknown circuit", teardownMsg.CircuitID)
		return
	}

	// Only allow teardown initiated by the previous hop in the circuit path
	if circuit.PrevPeer != remotePeer {
		r.logger.Warnf("Circuit %s: Unauthorized teardown attempt from %s (expected %s)", teardownMsg.CircuitID, remotePeer.ShortString(), circuit.PrevPeer.ShortString())
		return
	}

	// Forward the teardown if this is not the exit node
	if !circuit.IsExitNode {
		err := r.forwardCircuitTeardown(circuit, &teardownMsg)
		if err != nil {
			r.logger.Errorf("Circuit %s: Failed to forward teardown request: %v", teardownMsg.CircuitID, err)
			// Continue with local teardown anyway
		}
	}

	// Perform local teardown using string ID
	r.teardownCircuit(teardownMsg.CircuitID)
}

// forwardCircuitTeardown sends a teardown message to the next hop.
func (r *Relay) forwardCircuitTeardown(circuit *Circuit, msg *CircuitTeardownMessage) error {
	// Use the dedicated CircuitTeardownProtocol stream.
	tdStream, err := r.host.NewStream(r.ctx, circuit.NextPeer, CircuitTeardownProtocol)
	if err != nil {
		// Cannot reach next hop, maybe already down. Log and proceed with local teardown.
		return fmt.Errorf("failed to open teardown stream to %s: %w", circuit.NextPeer.ShortString(), err)
	}
	defer tdStream.Close()

	// Assuming CircuitTeardownMessage has CircuitID (string)
	err = WriteGob(tdStream, msg)
	if err != nil {
		return fmt.Errorf("failed to write teardown message to %s: %w", circuit.NextPeer.ShortString(), err)
	}
	r.logger.Debugf("Circuit %s: Forwarded teardown request to %s", msg.CircuitID, circuit.NextPeer.ShortString())
	return nil
}

// teardownCircuit removes a circuit from the relay's state and closes streams.
func (r *Relay) teardownCircuit(circuitID string) { // Changed param type to string
	r.circuitsMu.Lock()
	defer r.circuitsMu.Unlock()

	circuit, ok := r.circuits[circuitID]
	if !ok {
		r.logger.Debugf("Circuit %s: Already torn down or never existed.", circuitID)
		return // Already gone
	}

	r.logger.Infof("Circuit %s: Tearing down.", circuitID)

	// Close the stream to the *next* hop, if it exists and is open
	circuit.streamMu.Lock()
	if circuit.Stream != nil {
		circuit.Stream.Close() // Close gracefully first
		circuit.Stream = nil
	}
	circuit.streamMu.Unlock()

	// Remove from the map using string ID
	delete(r.circuits, circuitID)
}

// --- Background Tasks ---

// cleanupStaleCircuitsLoop periodically checks for and removes inactive circuits.
func (r *Relay) cleanupStaleCircuitsLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanupStaleCircuits(interval * 2) // Remove circuits inactive for 2 intervals
		case <-r.ctx.Done():
			r.logger.Debug("Stopping stale circuit cleanup loop.") // Changed log level
			return
		}
	}
}

// cleanupStaleCircuits removes circuits that haven't seen activity for the given duration.
func (r *Relay) cleanupStaleCircuits(maxIdleTime time.Duration) {
	r.logger.Debugf("Running stale circuit cleanup (max idle: %s)", maxIdleTime)
	staleIDs := make([]string, 0) // Changed slice type to string
	now := time.Now()

	r.circuitsMu.RLock()
	for id, circuit := range r.circuits {
		if now.Sub(circuit.LastActive) > maxIdleTime {
			staleIDs = append(staleIDs, id)
		}
	}
	r.circuitsMu.RUnlock() // Release read lock before acquiring write lock

	if len(staleIDs) > 0 {
		r.logger.Infof("Cleaning up %d stale circuits", len(staleIDs))
		// Acquire write lock to perform teardown is handled by teardownCircuit
		for _, id := range staleIDs {
			// Need to re-acquire read lock briefly to get LastActive time for logging,
			// or accept that the log message might be slightly inaccurate if the circuit
			// is modified between the RUnlock above and the teardownCircuit call.
			// Let's keep it simple for now.
			r.logger.Debugf("Tearing down stale circuit %s", id)
			// TODO: Should we attempt to forward a teardown message for stale circuits? Probably not.
			r.teardownCircuit(id) // Use string ID
		}
	}
}

// --- Helper Structs/Functions (Should move to packet.go ideally) ---

// InnerPayload defines the actual application data structure.
// Moved definition here temporarily to resolve compilation errors.
/* // REMOVED - Defined in packet.go now
type InnerPayload struct {
Type      uint    // Changed to uint to match constants
Recipient peer.ID // Final destination PeerID (optional, might be implicit)
Data      []byte  // Application-specific data
// Add other fields like ReplyTo info if needed
}
*/

// DecodeInnerPayload deserializes the InnerPayload struct.
// Moved definition here temporarily.
/* // REMOVED - Defined in packet.go now
func DecodeInnerPayload(data []byte) (*InnerPayload, error) {
var ip InnerPayload
dec := gob.NewDecoder(bytes.NewReader(data))
if err := dec.Decode(&ip); err != nil {
return nil, fmt.Errorf("failed to decode as InnerPayload: %w", err)
}
return &ip, nil
}
*/

// LayeredPayload is assumed to be defined in packet.go
// type LayeredPayload struct {
//  NextHop peer.ID
//  Payload []byte // Encrypted data for the next hop
// }

// DecodeLayeredPayload is assumed to be defined in packet.go
// func DecodeLayeredPayload(data []byte) (*LayeredPayload, error) { ... }

// OnionPacket is assumed to be defined in packet.go
// type OnionPacket struct {
//  CircuitID        uuid.UUID
//  EncryptedPayload []byte
// }

// DecryptPayload is assumed to be defined in crypto.go
// func DecryptPayload(key, ciphertext []byte) ([]byte, error) { ... }

// GenerateEphemeralKeyPair is assumed to be defined in crypto.go
// func GenerateEphemeralKeyPair() ([]byte, []byte, error) { ... }

// DeriveSharedKey is assumed to be defined in crypto.go
// func DeriveSharedKey(privKey, pubKey []byte) ([]byte, error) { ... }
