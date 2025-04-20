package onion

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"net" // Still needed for mock stream implementation
	"sync"
	"testing"
	"time"

	"bufio"   // Added for reliable line reading
	"strings" // Added for TrimSpace

	"github.com/libp2p/go-libp2p/core/connmgr" // Added for ConnManager
	"github.com/libp2p/go-libp2p/core/event"   // Needed for EventBus
	p2pnet "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore" // Added for Peerstore interface
	"github.com/libp2p/go-libp2p/core/protocol"  // Needed for Host interface
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock Libp2p Host Implementation ---

// MockHost simulates a libp2p host for testing.
type MockHost struct {
	id             peer.ID
	store          map[peer.ID]*MockHost // Simple way to find other mock hosts
	streamHandlers map[protocol.ID]p2pnet.StreamHandler
	privKey        []byte // Host's long-term private key (if needed, not used here)
	pubKey         []byte // Host's long-term public key (if needed, not used here)
	mu             sync.Mutex
	listener       net.Listener // Simulate listening for connections
	isClosed       bool
	t              *testing.T
}

// MockStream simulates a libp2p network stream.
type MockStream struct {
	conn          net.Conn
	protocol      protocol.ID
	localPeer     peer.ID
	remotePeer    peer.ID
	stat          p2pnet.Stats       // Ensure qualification
	ctx           context.Context    // Added context
	cancel        context.CancelFunc // Added cancel func
	readDeadline  time.Time
	writeDeadline time.Time
}

// MockConn simulates a network connection.
type MockConn struct {
	reader        io.Reader
	writer        io.Writer
	closed        bool
	mu            sync.Mutex
	localAddr     net.Addr
	remoteAddr    net.Addr
	readDeadline  time.Time
	writeDeadline time.Time
}

// Implement net.Conn interface for MockConn
func (mc *MockConn) Read(b []byte) (n int, err error) {
	mc.mu.Lock()
	deadline := mc.readDeadline
	mc.mu.Unlock()

	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, fmt.Errorf("read timeout") // Simulate timeout
	}

	// Basic read simulation
	if mc.closed {
		return 0, io.EOF
	}
	// This simple simulation might block if reader blocks. Needs improvement for timeouts.
	n, err = mc.reader.Read(b)
	if err != nil && err != io.EOF {
		// fmt.Printf("MockConn Read Error: %v\n", err) // Debug
	} else if err == io.EOF {
		// fmt.Println("MockConn Read EOF") // Debug
		mc.Close() // Close on EOF
	}
	return n, err
}

func (mc *MockConn) Write(b []byte) (n int, err error) {
	mc.mu.Lock()
	deadline := mc.writeDeadline
	mc.mu.Unlock()

	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, fmt.Errorf("write timeout") // Simulate timeout
	}

	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return 0, fmt.Errorf("use of closed network connection")
	}
	mc.mu.Unlock()
	// fmt.Printf("MockConn Write: %d bytes\n", len(b)) // Debug
	n, err = mc.writer.Write(b)
	if err != nil {
		// fmt.Printf("MockConn Write Error: %v\n", err) // Debug
		mc.Close() // Close on write error?
	}
	return n, err
}

func (mc *MockConn) Close() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.closed {
		return nil
	}
	mc.closed = true
	// fmt.Println("MockConn Close") // Debug
	// Close underlying pipes if they are closers
	// Close reader if it's a closer
	if readerCloser, ok := mc.reader.(io.Closer); ok {
		readerCloser.Close() // Close the reader first
	}

	// Close writer if it's a closer
	if writerCloser, ok := mc.writer.(io.Closer); ok {
		// If they are the same underlying resource, the second close should ideally be a no-op.
		writerCloser.Close()
	}
	return nil
}

// Stat returns dummy statistics.
func (mc *MockConn) Stat() p2pnet.Stats {
	return p2pnet.Stats{} // Ensure qualification
}

func (mc *MockConn) LocalAddr() net.Addr  { return mc.localAddr }
func (mc *MockConn) RemoteAddr() net.Addr { return mc.remoteAddr }
func (mc *MockConn) SetDeadline(t time.Time) error {
	mc.mu.Lock()
	mc.readDeadline = t
	mc.writeDeadline = t
	mc.mu.Unlock()
	return nil
}
func (mc *MockConn) SetReadDeadline(t time.Time) error {
	mc.mu.Lock()
	mc.readDeadline = t
	mc.mu.Unlock()
	return nil
}
func (mc *MockConn) SetWriteDeadline(t time.Time) error {
	mc.mu.Lock()
	mc.writeDeadline = t
	mc.mu.Unlock()
	return nil
}

// Implement network.Stream interface for MockStream
func (ms *MockStream) Read(p []byte) (n int, err error)   { return ms.conn.Read(p) }
func (ms *MockStream) Write(p []byte) (n int, err error)  { return ms.conn.Write(p) }
func (ms *MockStream) Close() error                       { return ms.conn.Close() }
func (ms *MockStream) Reset() error                       { ms.cancel(); return ms.conn.Close() } // Also cancel context on reset
func (ms *MockStream) SetDeadline(t time.Time) error      { return ms.conn.SetDeadline(t) }
func (ms *MockStream) SetReadDeadline(t time.Time) error  { return ms.conn.SetReadDeadline(t) }
func (ms *MockStream) SetWriteDeadline(t time.Time) error { return ms.conn.SetWriteDeadline(t) }
func (ms *MockStream) Protocol() protocol.ID              { return ms.protocol }
func (ms *MockStream) Stat() p2pnet.Stats                 { return ms.stat } // Ensure qualification
func (ms *MockStream) Conn() p2pnet.Conn                  { return nil }     // Simplify: return nil for underlying Conn

// CloseRead closes the read side of the stream.
func (ms *MockStream) CloseRead() error {
	if connWithCloseRead, ok := ms.conn.(interface{ CloseRead() error }); ok {
		return connWithCloseRead.CloseRead()
	}
	// Fallback or error if the underlying connection doesn't support CloseRead
	return fmt.Errorf("underlying connection type %T does not support CloseRead", ms.conn)
}

// CloseWrite closes the write side of the stream.
func (ms *MockStream) CloseWrite() error {
	if connWithCloseWrite, ok := ms.conn.(interface{ CloseWrite() error }); ok {
		return connWithCloseWrite.CloseWrite()
	}
	// Fallback or error if the underlying connection doesn't support CloseWrite
	return fmt.Errorf("underlying connection type %T does not support CloseWrite", ms.conn)
}

// ResetWithError resets the stream with an error code, matching the interface.
func (ms *MockStream) ResetWithError(code p2pnet.StreamErrorCode) error {
	ms.cancel() // Cancel context
	// Attempt to close underlying connection, potentially signaling error
	// This mock doesn't propagate the specific error well. Consider logging the code.
	_ = ms.conn.Close()
	return nil // Or return the passed error? Interface isn't specific.
}

// ID returns a dummy stream ID.
func (ms *MockStream) ID() string {
	// Generate a simple ID based on peers and protocol for basic uniqueness
	return fmt.Sprintf("%s-%s-%s", ms.localPeer.String(), ms.remotePeer.String(), ms.protocol)
}

func (ms *MockStream) LocalPeer() peer.ID       { return ms.localPeer }
func (ms *MockStream) RemotePeer() peer.ID      { return ms.remotePeer }
func (ms *MockStream) Context() context.Context { return ms.ctx } // Return stream's context

// Scope returns a nil stream scope (not implemented in mock).
func (ms *MockStream) Scope() p2pnet.StreamScope {
	return nil // Mock doesn't implement stream scoping
}

// SetProtocol sets the protocol ID for the stream (dummy implementation).
func (ms *MockStream) SetProtocol(id protocol.ID) error {
	ms.protocol = id
	return nil
}

// NewMockHost creates a mock host.
func NewMockHost(t *testing.T, store map[peer.ID]*MockHost) *MockHost {
	id, _ := peer.Decode("12D3KooWExamplePeerID" + fmt.Sprintf("%d", len(store)+1)) // Simple unique ID generation
	listener, err := net.Listen("tcp", "127.0.0.1:0")                               // Listen on a random port
	require.NoError(t, err)

	h := &MockHost{
		id:             id,
		store:          store,
		streamHandlers: make(map[protocol.ID]p2pnet.StreamHandler),
		listener:       listener,
		t:              t,
	}
	store[id] = h     // Register self in the store
	go h.acceptLoop() // Start listening for incoming mock connections
	return h
}

func (mh *MockHost) ID() peer.ID { return mh.id }

// Addrs returns the listening addresses of the mock host.
func (mh *MockHost) Addrs() []multiaddr.Multiaddr {
	// Convert net.Addr to multiaddr.Multiaddr
	maddr, err := manet.FromNetAddr(mh.listener.Addr())
	if err != nil {
		mh.t.Logf("Error converting listener address to multiaddr: %v", err)
		return nil
	}
	return []multiaddr.Multiaddr{maddr}
}

// ConnManager returns a nil connection manager (not implemented in mock).
func (mh *MockHost) ConnManager() connmgr.ConnManager {
	return nil // Mock doesn't manage connections in detail
}

func (mh *MockHost) SetStreamHandler(pid protocol.ID, handler p2pnet.StreamHandler) {
	mh.mu.Lock()
	mh.streamHandlers[pid] = handler
	mh.mu.Unlock()
}

// RemoveStreamHandler removes a stream handler (mock implementation).
func (mh *MockHost) RemoveStreamHandler(pid protocol.ID) {
	mh.mu.Lock()
	delete(mh.streamHandlers, pid)
	mh.mu.Unlock()
}

// SetStreamHandlerMatch sets a stream handler with a matching function (mock implementation).
// For simplicity, this mock ignores the matching function and calls SetStreamHandler.
func (mh *MockHost) SetStreamHandlerMatch(pid protocol.ID, m func(protocol.ID) bool, handler p2pnet.StreamHandler) {
	mh.SetStreamHandler(pid, handler) // Ignore the matching function in the mock
}

// acceptLoop simulates accepting incoming connections.
func (mh *MockHost) acceptLoop() {
	for {
		conn, err := mh.listener.Accept()
		if err != nil {
			mh.mu.Lock()
			closed := mh.isClosed
			mh.mu.Unlock()
			if !closed {
				// mh.t.Logf("MockHost %s: Accept error: %v", mh.id, err)
			}
			return // Stop loop if listener is closed or error occurs
		}

		// Simulate protocol negotiation - read the protocol ID sent by the initiator
		// In a real scenario, this involves multistream-select.
		// Here, we assume the initiator writes the protocol ID first.
		go mh.handleIncomingConn(conn)
	}
}

// handleIncomingConn determines the protocol and calls the handler.
func (mh *MockHost) handleIncomingConn(conn net.Conn) {
	// Use bufio.Reader for reliable line reading
	reader := bufio.NewReader(conn)
	protocolLine, err := reader.ReadString('\n')
	if err != nil {
		// mh.t.Logf("MockHost %s: Error reading protocol ID line: %v", mh.id, err)
		conn.Close()
		return
	}
	pid := protocol.ID(strings.TrimSpace(protocolLine)) // Use strings.TrimSpace
	// mh.t.Logf("MockHost %s: Received connection for protocol %s", mh.id, pid)

	mh.mu.Lock()
	handler, ok := mh.streamHandlers[pid]
	mh.mu.Unlock()

	if !ok {
		// mh.t.Logf("MockHost %s: No handler found for protocol %s", mh.id, pid)
		conn.Close() // Or send back protocol error
		return
	}

	// Create a mock stream. Pass the ORIGINAL conn. The bufio.Reader was only
	// used for the initial protocol read. Subsequent reads (like gob decoding)
	// will use the original connection directly. This assumes the client doesn't
	// send gob data immediately interleaved with the protocol ID line ending.
	dummyRemoteID, _ := peer.Decode("12D3KooWDummyRemotePeerID")
	ctx, cancel := context.WithCancel(context.Background())
	stat := p2pnet.Stats{}

	mockStream := &MockStream{
		conn:       conn, // Use original conn
		protocol:   pid,
		localPeer:  mh.id,
		remotePeer: dummyRemoteID,
		stat:       stat,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Call the handler
	handler(mockStream)
}

// NewStream simulates opening a new stream to a remote peer.
func (mh *MockHost) NewStream(ctx context.Context, p peer.ID, pids ...protocol.ID) (p2pnet.Stream, error) {
	mh.mu.Lock()
	targetHost, ok := mh.store[p]
	mh.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("mock host %s not found in store", p)
	}

	if len(pids) == 0 {
		return nil, fmt.Errorf("no protocol ID specified")
	}
	pid := pids[0] // Use the first protocol ID

	// Connect to the target host's listener
	conn, err := net.Dial("tcp", targetHost.listener.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("failed to dial mock host %s: %w", p, err)
	}

	// Simulate protocol negotiation: Write the protocol ID
	_, err = conn.Write([]byte(string(pid) + "\n"))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write protocol ID to mock host %s: %w", p, err)
	}

	// Create a mock stream
	streamCtx, streamCancel := context.WithCancel(ctx) // Inherit context

	// Basic fallback stat
	stat := p2pnet.Stats{} // Ensure qualification

	mockStream := &MockStream{
		conn:       conn,
		protocol:   pid,
		localPeer:  mh.id,
		remotePeer: p,    // We know the remote peer here
		stat:       stat, // Use initialized stat
		ctx:        streamCtx,
		cancel:     streamCancel,
	}

	return mockStream, nil
}

// Close shuts down the mock host.
func (mh *MockHost) Close() error {
	mh.mu.Lock()
	if mh.isClosed {
		mh.mu.Unlock()
		return nil
	}
	mh.isClosed = true
	mh.mu.Unlock()
	return mh.listener.Close()
}

// Connect simulates connecting to a peer (dummy implementation).
func (mh *MockHost) Connect(ctx context.Context, pi peer.AddrInfo) error {
	// In a real host, this would establish a connection.
	// Mock logic: Check if peer exists in store, maybe simulate latency/error.
	mh.mu.Lock()
	_, ok := mh.store[pi.ID]
	mh.mu.Unlock()
	if !ok {
		return fmt.Errorf("mock connect error: peer %s not found in store", pi.ID)
	}
	// Simulate successful connection
	// mh.t.Logf("MockHost %s: Connect called for peer %s", mh.id, pi.ID)
	return nil
}

// EventBus returns a nil event bus (not implemented in mock).
func (mh *MockHost) EventBus() event.Bus {
	return nil // Mock doesn't implement event bus
}

// Mux returns nil (not implemented in mock).
func (mh *MockHost) Mux() protocol.Switch {
	return nil // Mock doesn't implement protocol multiplexer
}

// Network returns a nil network interface (mock implementation).
func (mh *MockHost) Network() p2pnet.Network {
	return nil // Mock doesn't provide a full network implementation
}

// Peerstore returns a nil peerstore (mock implementation).
func (mh *MockHost) Peerstore() peerstore.Peerstore {
	return nil // Mock doesn't provide a peerstore implementation
}

// --- Mock Relay Logic ---

// RelayState stores the state of a circuit from a relay's perspective.
type RelayCircuitState struct {
	circuitID    string
	incomingPeer peer.ID // Peer we received the setup/extend from
	outgoingPeer peer.ID // Peer we forwarded the extend to (if not exit)
	incomingKey  []byte  // Symmetric key shared with incomingPeer for this circuit
	outgoingKey  []byte  // Symmetric key shared with outgoingPeer for this circuit (derived by *client*)
	isExit       bool
	mu           sync.Mutex
	setupStream  p2pnet.Stream             // Store the stream used for setup? Or assume one stream per connection?
	dataStreams  map[peer.ID]p2pnet.Stream // Track data streams?
}

// MockRelay holds state for a relay node in the test.
type MockRelayNode struct {
	host         *MockHost
	circuits     map[string]*RelayCircuitState // Map circuitID to state
	circuitsMu   sync.Mutex
	ephemPrivKey []byte // Relay's ephemeral private key for a specific setup
	ephemPubKey  []byte // Relay's ephemeral public key for a specific setup
	t            *testing.T
}

func NewMockRelayNode(t *testing.T, store map[peer.ID]*MockHost) *MockRelayNode {
	h := NewMockHost(t, store)
	r := &MockRelayNode{
		host:     h,
		circuits: make(map[string]*RelayCircuitState),
		t:        t,
	}
	h.SetStreamHandler(protocol.ID(CircuitSetupProtocol), r.handleCircuitSetupStream)
	h.SetStreamHandler(protocol.ID(RelayProtocol), r.handleRelayStream)
	return r
}

// handleCircuitSetupStream handles incoming streams for circuit setup/extension/teardown.
func (r *MockRelayNode) handleCircuitSetupStream(stream p2pnet.Stream) {
	defer stream.Close() // Ensure stream is closed when handler exits

	// Read the setup message
	var req CircuitSetupMessage
	err := ReadGob(stream, &req)
	if err != nil {
		r.t.Logf("Relay %s: Error reading setup message: %v", r.host.ID(), err)
		return
	}
	// r.t.Logf("Relay %s: Received setup message: Type=%d, CircuitID=%s", r.host.ID(), req.Type, req.CircuitID)

	switch req.Type {
	case TypeEstablish:
		r.handleEstablish(stream, req)
	case TypeExtend:
		r.handleExtend(stream, req)
	case TypeTeardown:
		r.handleTeardown(stream, req)
	default:
		r.t.Logf("Relay %s: Received unknown setup message type: %d", r.host.ID(), req.Type)
		// Send error response?
	}
}

// handleEstablish processes a TypeEstablish message.
func (r *MockRelayNode) handleEstablish(stream p2pnet.Stream, req CircuitSetupMessage) {
	// Type assert stream to access mock-specific methods like RemotePeer()
	mockStream, ok := stream.(*MockStream)
	if !ok {
		r.t.Logf("Relay %s (Establish): Error: received stream is not a *MockStream", r.host.ID())
		resp := CircuitSetupResponse{Type: TypeEstablished, CircuitID: req.CircuitID, Status: StatusError}
		_ = WriteGob(stream, &resp) // Use original stream for response
		return
	}

	// 1. Generate relay's ephemeral keys for this circuit hop
	relayHopPrivKey, relayHopPubKeyBytes, err := GenerateEphemeralKeyPair()
	if err != nil {
		r.t.Logf("Relay %s (Establish): Failed to generate keys: %v", r.host.ID(), err)
		// Send error response
		resp := CircuitSetupResponse{Type: TypeEstablished, CircuitID: req.CircuitID, Status: StatusError}
		_ = WriteGob(stream, &resp)
		return
	}
	r.ephemPrivKey = relayHopPrivKey // Store for key derivation
	r.ephemPubKey = relayHopPubKeyBytes

	// 2. Derive shared key with the client
	clientHopPubKeyBytes := req.PublicKey
	sharedKey, err := DeriveSharedKey(relayHopPrivKey, clientHopPubKeyBytes)
	if err != nil {
		r.t.Logf("Relay %s (Establish): Failed to derive shared key: %v", r.host.ID(), err)
		resp := CircuitSetupResponse{Type: TypeEstablished, CircuitID: req.CircuitID, Status: StatusError}
		_ = WriteGob(stream, &resp)
		return
	}

	// 3. Store circuit state
	circuitState := &RelayCircuitState{
		circuitID:    req.CircuitID,
		incomingPeer: mockStream.RemotePeer(), // Use RemotePeer from type-asserted stream
		incomingKey:  sharedKey,
		isExit:       req.NextHopPeerID == "", // It's an exit node if NextHopPeerID is empty
		outgoingPeer: req.NextHopPeerID,
		setupStream:  mockStream, // Store the stream for potential future use within this circuit context
	}
	r.circuitsMu.Lock()
	r.circuits[req.CircuitID] = circuitState
	r.circuitsMu.Unlock()

	// r.t.Logf("Relay %s (Establish): Circuit %s established. IsExit=%t, NextHop=%s", r.host.ID(), req.CircuitID, circuitState.isExit, req.NextHopPeerID)

	// 4. Send Established response
	resp := CircuitSetupResponse{
		Type:      TypeEstablished,
		CircuitID: req.CircuitID,
		Status:    StatusOK,
		PublicKey: relayHopPubKeyBytes,
	}
	err = WriteGob(stream, &resp)
	if err != nil {
		r.t.Logf("Relay %s (Establish): Failed to send Established response: %v", r.host.ID(), err)
		// Clean up circuit state?
		r.circuitsMu.Lock()
		delete(r.circuits, req.CircuitID)
		r.circuitsMu.Unlock()
	} else {
		// r.t.Logf("Relay %s (Establish): Sent Established response for %s", r.host.ID(), req.CircuitID)
		// If this relay needs to extend further, it should initiate the extension now.
		// This requires the relay to act as a client for the *next* hop.
		// The current test structure assumes the client drives all extensions via the entry node stream.
		// We will follow the test structure for now.
	}
}

// handleExtend processes a TypeExtend message (received from previous hop).
func (r *MockRelayNode) handleExtend(stream p2pnet.Stream, req CircuitSetupMessage) {
	// Type assert stream to access mock-specific methods like RemotePeer()
	mockStream, ok := stream.(*MockStream)
	if !ok {
		r.t.Logf("Relay %s (Extend): Error: received stream is not a *MockStream", r.host.ID())
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError}
		_ = WriteGob(stream, &resp) // Use original stream for response
		return
	}

	// This function simulates the relay receiving an Extend request,
	// forwarding it to the next hop, and relaying the response back.
	// In the current test setup, the client sends Extend directly via the entry stream.
	// This handler simulates the *target* of the extension.

	// 1. Find the circuit state (should have been created by a previous Establish/Extend)
	//    This seems wrong based on test flow. The client sends Extend to R1, R1 forwards to R2.
	//    R2 handles it here. R2 needs the key shared with R1.
	//    The test setup doesn't model R1 forwarding to R2. It assumes client talks to R2 via R1's stream.
	//    Let's adapt to the test's simplified flow: This handler acts as the target relay (e.g., R2 or R3).

	// 2. Generate relay's ephemeral keys
	relayHopPrivKey, relayHopPubKeyBytes, err := GenerateEphemeralKeyPair()
	if err != nil {
		r.t.Logf("Relay %s (Extend): Failed to generate keys: %v", r.host.ID(), err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError}
		_ = WriteGob(stream, &resp) // Send error back on the incoming stream
		return
	}
	r.ephemPrivKey = relayHopPrivKey
	r.ephemPubKey = relayHopPubKeyBytes

	// 3. Derive shared key with the client (using client's pubkey from request)
	clientHopPubKeyBytes := req.PublicKey
	sharedKey, err := DeriveSharedKey(relayHopPrivKey, clientHopPubKeyBytes)
	if err != nil {
		r.t.Logf("Relay %s (Extend): Failed to derive shared key: %v", r.host.ID(), err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError}
		_ = WriteGob(stream, &resp)
		return
	}

	//  4. Store circuit state (or update if already exists?)
	//     In the test flow, this relay didn't handle the *previous* hop's setup directly.
	//     We need to store the key derived *now*.
	circuitState := &RelayCircuitState{
		circuitID:    req.CircuitID,
		incomingPeer: mockStream.RemotePeer(), // Use RemotePeer from type-asserted stream
		incomingKey:  sharedKey,               // Key shared with CLIENT for this hop
		isExit:       req.NextHopPeerID == "",
		outgoingPeer: req.NextHopPeerID,
		setupStream:  mockStream,
	}
	r.circuitsMu.Lock()
	// If state exists, update? Or assume this is the first time this relay sees the circuit?
	// Let's assume it's the first time for simplicity matching test flow.
	r.circuits[req.CircuitID] = circuitState
	r.circuitsMu.Unlock()

	// r.t.Logf("Relay %s (Extend): Circuit %s extended. IsExit=%t, NextHop=%s", r.host.ID(), req.CircuitID, circuitState.isExit, req.NextHopPeerID)

	// 5. Send Extended response back on the same stream
	resp := CircuitSetupResponse{
		Type:      TypeExtended,
		CircuitID: req.CircuitID,
		Status:    StatusOK,
		PublicKey: relayHopPubKeyBytes, // Send relay's public key back
	}
	err = WriteGob(stream, &resp)
	if err != nil {
		r.t.Logf("Relay %s (Extend): Failed to send Extended response: %v", r.host.ID(), err)
		r.circuitsMu.Lock()
		delete(r.circuits, req.CircuitID)
		r.circuitsMu.Unlock()
	} else {
		// r.t.Logf("Relay %s (Extend): Sent Extended response for %s", r.host.ID(), req.CircuitID)
		// If this relay needs to extend further (req.NextHopPeerID != ""),
		// the test flow assumes the client will send the next Extend message.
	}
}

// handleTeardown processes a TypeTeardown message.
func (r *MockRelayNode) handleTeardown(stream p2pnet.Stream, req CircuitSetupMessage) {
	r.circuitsMu.Lock()
	state, ok := r.circuits[req.CircuitID]
	if ok {
		// r.t.Logf("Relay %s: Tearing down circuit %s", r.host.ID(), req.CircuitID)
		delete(r.circuits, req.CircuitID)
		// If this relay had forwarded an extend, it should also send teardown downstream.
		// This requires storing the downstream hop and potentially the stream used.
		// For now, just delete local state.
		_ = state // Avoid unused variable error
	} else {
		// r.t.Logf("Relay %s: Received teardown for unknown circuit %s", r.host.ID(), req.CircuitID)
	}
	r.circuitsMu.Unlock()
	// No response needed for teardown. Close the stream.
	stream.Close()
}

// handleRelayStream handles incoming data streams.
func (r *MockRelayNode) handleRelayStream(stream p2pnet.Stream) {
	// This handler processes OnionPackets received over the RelayProtocol.
	defer stream.Close()

	// 1. Read the OnionPacket
	var packet OnionPacket
	err := ReadGob(stream, &packet)
	if err != nil {
		if err != io.EOF {
			r.t.Logf("Relay %s: Error reading onion packet: %v", r.host.ID(), err)
		}
		return
	}
	// r.t.Logf("Relay %s: Received data packet for circuit %s", r.host.ID(), packet.CircuitID)

	// 2. Find circuit state
	r.circuitsMu.Lock()
	state, ok := r.circuits[packet.CircuitID]
	r.circuitsMu.Unlock()
	if !ok {
		r.t.Logf("Relay %s: Received data packet for unknown circuit %s", r.host.ID(), packet.CircuitID)
		return
	}

	//  3. Decrypt payload using the key for this hop
	//     Which key? The key shared with the *client* for this hop.
	//     The circuit state stores `incomingKey` which should be this key.
	decryptedBytes, err := DecryptPayload(state.incomingKey, packet.EncryptedPayload)
	if err != nil {
		r.t.Logf("Relay %s (Circuit %s): Failed to decrypt payload: %v", r.host.ID(), packet.CircuitID, err)
		return
	}

	// 4. Check if this is the exit node
	if state.isExit {
		// 4a. Decode as InnerPayload
		innerPayload, err := DecodeInnerPayload(decryptedBytes)
		if err != nil {
			r.t.Logf("Relay %s (Exit, Circuit %s): Failed to decode inner payload: %v", r.host.ID(), packet.CircuitID, err)
			return
		}
		r.t.Logf("Relay %s (Exit, Circuit %s): Successfully decrypted InnerPayload: %s", r.host.ID(), packet.CircuitID, string(innerPayload.Data))

		// --- Simulate processing and response ---
		// In a real scenario, send innerPayload.Data to the final destination.
		// Here, we just simulate receiving it and sending a mock response back.
		mockResponseData := []byte("Mock Response Data from " + r.host.ID().String())
		innerResponse := InnerPayload{
			// MessageType: MessageTypeResponse, // Example
			Data: mockResponseData,
		}
		var innerRespBuf bytes.Buffer
		err = gob.NewEncoder(&innerRespBuf).Encode(&innerResponse)
		if err != nil {
			r.t.Logf("Relay %s (Exit, Circuit %s): Failed to encode response: %v", r.host.ID(), packet.CircuitID, err)
			return
		}

		// Now, send the response back through the circuit. This requires layered encryption in reverse.
		// TODO: Implement response path simulation. This is complex.
		// For now, the SendData test will only verify data reaches the exit.

	} else {
		// 4b. Decode as LayeredPayload
		layeredPayload, err := DecodeLayeredPayload(decryptedBytes)
		if err != nil {
			r.t.Logf("Relay %s (Relay, Circuit %s): Failed to decode layered payload: %v", r.host.ID(), packet.CircuitID, err)
			return
		}

		// 5. Forward the inner payload to the next hop
		nextHopID := layeredPayload.NextHop
		payloadToForward := layeredPayload.Payload // This is already encrypted for the next hop

		// Construct the OnionPacket for the next hop
		forwardPacket := &OnionPacket{
			CircuitID:        packet.CircuitID,             // Use the same circuit ID
			HopInfo:          HopInfo{NextPeer: nextHopID}, // HopInfo might be less relevant here? Or should point to the *next* next hop? Let's keep it simple.
			EncryptedPayload: payloadToForward,
		}

		// Open a *new* stream to the next hop using RelayProtocol
		// r.t.Logf("Relay %s (Circuit %s): Forwarding data to next hop %s", r.host.ID(), packet.CircuitID, nextHopID)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		nextStream, err := r.host.NewStream(ctx, nextHopID, protocol.ID(RelayProtocol))
		if err != nil {
			r.t.Logf("Relay %s (Circuit %s): Failed to open stream to next hop %s: %v", r.host.ID(), packet.CircuitID, nextHopID, err)
			return
		}
		defer nextStream.Close()

		// Send the packet
		err = WriteGob(nextStream, forwardPacket)
		if err != nil {
			r.t.Logf("Relay %s (Circuit %s): Failed to forward packet to next hop %s: %v", r.host.ID(), packet.CircuitID, nextHopID, err)
			_ = nextStream.Reset()
		} else {
			// r.t.Logf("Relay %s (Circuit %s): Successfully forwarded data to %s", r.host.ID(), packet.CircuitID, nextHopID)
		}
	}
}

// --- Tests ---

func TestClientCircuitBuilder_BuildCircuit_Success_MultiHop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Store for mock hosts to find each other
	hostStore := make(map[peer.ID]*MockHost)

	// Create mock relays
	relay1 := NewMockRelayNode(t, hostStore)
	defer relay1.host.Close()
	relay2 := NewMockRelayNode(t, hostStore)
	defer relay2.host.Close()
	relay3 := NewMockRelayNode(t, hostStore)
	defer relay3.host.Close()

	// Create client host
	clientHost := NewMockHost(t, hostStore)
	defer clientHost.Close()

	// Give listeners time to start
	time.Sleep(100 * time.Millisecond)

	// Create CircuitBuilder
	builder, err := NewCircuitBuilder(clientHost)
	require.NoError(t, err)

	// Define circuit path
	path := []peer.ID{relay1.host.ID(), relay2.host.ID(), relay3.host.ID()}

	// Build the circuit
	circuit, err := builder.BuildCircuit(ctx, path)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, circuit)
	require.NotEmpty(t, circuit.ID)
	assert.Equal(t, path, circuit.Path)
	assert.Equal(t, relay1.host.ID(), circuit.EntryNode)
	assert.Equal(t, relay3.host.ID(), circuit.ExitNode)
	require.Equal(t, len(path), len(circuit.Keys), "Number of keys should match path length")
	assert.NotNil(t, circuit.Stream, "Circuit stream should not be nil")
	assert.Equal(t, clientHost.ID(), circuit.host.ID())

	// Check keys are not empty
	for i, key := range circuit.Keys {
		assert.NotEmpty(t, key, fmt.Sprintf("Key for hop %d should not be empty", i))
		assert.Len(t, key, 32, fmt.Sprintf("Key for hop %d should be 32 bytes", i)) // SHA256 output size
	}

	// Verify relay states (basic check)
	relay1.circuitsMu.Lock()
	r1State, ok1 := relay1.circuits[circuit.ID]
	relay1.circuitsMu.Unlock()
	require.True(t, ok1, "Relay 1 should have state for circuit %s", circuit.ID)
	assert.False(t, r1State.isExit)
	assert.Equal(t, relay2.host.ID(), r1State.outgoingPeer) // R1 should know next hop is R2

	relay2.circuitsMu.Lock()
	r2State, ok2 := relay2.circuits[circuit.ID]
	relay2.circuitsMu.Unlock()
	require.True(t, ok2, "Relay 2 should have state for circuit %s", circuit.ID)
	assert.False(t, r2State.isExit)
	assert.Equal(t, relay3.host.ID(), r2State.outgoingPeer) // R2 should know next hop is R3

	relay3.circuitsMu.Lock()
	r3State, ok3 := relay3.circuits[circuit.ID]
	relay3.circuitsMu.Unlock()
	require.True(t, ok3, "Relay 3 should have state for circuit %s", circuit.ID)
	assert.True(t, r3State.isExit) // R3 should know it's the exit
	assert.Equal(t, peer.ID(""), r3State.outgoingPeer)

	// Close the circuit
	err = circuit.Close()
	assert.NoError(t, err)
	assert.Nil(t, circuit.Stream, "Circuit stream should be nil after close")

	// Verify relay state removed after close (eventually)
	// Note: Teardown propagation isn't fully implemented in mocks, so state might linger.
	// We only check R1 as it receives the direct teardown message.
	time.Sleep(50 * time.Millisecond) // Give time for teardown handler
	relay1.circuitsMu.Lock()
	_, ok1AfterClose := relay1.circuits[circuit.ID]
	relay1.circuitsMu.Unlock()
	assert.False(t, ok1AfterClose, "Relay 1 state should be removed after circuit close")

}

func TestClientCircuit_SendData_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hostStore := make(map[peer.ID]*MockHost)
	relay1 := NewMockRelayNode(t, hostStore)
	defer relay1.host.Close()
	relay2 := NewMockRelayNode(t, hostStore)
	defer relay2.host.Close()
	relay3 := NewMockRelayNode(t, hostStore) // Exit node
	defer relay3.host.Close()
	clientHost := NewMockHost(t, hostStore)
	defer clientHost.Close()

	time.Sleep(100 * time.Millisecond)

	builder, err := NewCircuitBuilder(clientHost)
	require.NoError(t, err)
	path := []peer.ID{relay1.host.ID(), relay2.host.ID(), relay3.host.ID()}

	// Build circuit
	circuit, err := builder.BuildCircuit(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, circuit)
	defer circuit.Close() // Ensure circuit is closed eventually

	// Data to send
	testData := []byte("Hello Onion World!")
	destinationPeer := relay3.host.ID() // Sending *through* R3 to some final destination (conceptually)

	// Use a WaitGroup to wait for the exit node handler to log success
	var wg sync.WaitGroup
	wg.Add(1)

	// Modify exit node's data handler to signal success
	originalHandler := relay3.host.streamHandlers[protocol.ID(RelayProtocol)]
	relay3.host.SetStreamHandler(protocol.ID(RelayProtocol), func(stream p2pnet.Stream) {
		// Call original handler first
		originalHandler(stream)
		// If original handler processed data successfully (indicated by log message), signal WaitGroup
		// This requires modifying the original handler to provide feedback, or checking logs.
		// Simplification: Assume if the handler runs without panic/error log, it worked.
		// We rely on the log message inside handleRelayStream for verification.
		// Let's add a channel to signal data reception.
		// This requires modifying MockRelayNode and handleRelayStream.

		// --- Alternative: Check logs ---
		// This is brittle. Let's modify the handler directly for the test.

		relay3.host.SetStreamHandler(protocol.ID(RelayProtocol), func(stream p2pnet.Stream) {
			defer stream.Close()
			var packet OnionPacket
			err := ReadGob(stream, &packet)
			if err != nil {
				return
			}

			relay3.circuitsMu.Lock()
			state, ok := relay3.circuits[packet.CircuitID]
			relay3.circuitsMu.Unlock()
			if !ok {
				return
			}

			decryptedBytes, err := DecryptPayload(state.incomingKey, packet.EncryptedPayload)
			if err != nil {
				return
			}

			if state.isExit {
				innerPayload, err := DecodeInnerPayload(decryptedBytes)
				if err != nil {
					return
				}
				// Check if data matches
				if bytes.Equal(innerPayload.Data, testData) {
					t.Logf("Relay %s (Exit, Circuit %s): *** Received expected data: %s ***", relay3.host.ID(), packet.CircuitID, string(innerPayload.Data))
					wg.Done() // Signal success
				} else {
					t.Logf("Relay %s (Exit, Circuit %s): !!! Received unexpected data: %s !!!", relay3.host.ID(), packet.CircuitID, string(innerPayload.Data))
				}
				// No response sending simulation here yet
			} else {
				// Should not happen if R3 is exit
			}
		})

	}) // End of handler modification - This is messy, needs refinement.

	// Send data
	err = circuit.SendData(ctx, destinationPeer, testData)
	require.NoError(t, err)

	// Wait for exit node to signal data reception or timeout
	waitTimeout := time.After(5 * time.Second)
	select {
	case <-waitTimeout:
		t.Fatal("Timeout waiting for exit node to receive data")
	case <-func() chan struct{} { done := make(chan struct{}); go func() { wg.Wait(); close(done) }(); return done }():
		// Success! Data was received by the exit node handler.
		t.Log("Successfully verified data reception at exit node.")
	}

	// Restore original handler (optional, good practice)
	relay3.host.SetStreamHandler(protocol.ID(RelayProtocol), originalHandler)
}

// TODO: Add more tests:
// - BuildCircuit failure (e.g., relay unreachable, bad handshake response)
// - SendData failure (e.g., circuit closed, relay error during forwarding)
// - Teardown propagation test
// - Single hop circuit build and send
// - Concurrent SendData calls (if circuit/stream designed for it)
