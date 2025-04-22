package onion

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand" // Added for key generation
	"encoding/gob"
	"errors"
	"fmt"
	"io"  // Renamed to avoid conflict with crypto/rand
	"net" // Still needed for mock stream implementation
	"strings"
	"sync"
	"testing"
	"time"

	// Added for reliable line reading
	// Added for TrimSpace

	"github.com/libp2p/go-libp2p/core/connmgr"          // Added for ConnManager
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto" // Added for key generation
	"github.com/libp2p/go-libp2p/core/event"            // Needed for EventBus
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
// It now uses io.Reader/Writer interfaces to allow decoupling from net.Conn,
// especially useful for handling buffered reading after protocol negotiation.
type MockStream struct {
	reader        io.Reader // Source for Read operations
	writer        io.Writer // Destination for Write operations
	closer        io.Closer // Underlying resource to close (e.g., net.Conn)
	protocol      protocol.ID
	localPeer     peer.ID
	remotePeer    peer.ID
	stat          p2pnet.Stats       // Ensure qualification
	ctx           context.Context    // Added context
	cancel        context.CancelFunc // Added cancel func
	readDeadline  time.Time          // Store deadlines locally
	writeDeadline time.Time          // Store deadlines locally
	deadlineMu    sync.Mutex         // Protect deadline access
	// Store the original connection if needed for Addr, specific resets, etc.
	// Or simplify the interface further. Let's keep it for now.
	conn net.Conn
}

// Implement network.Stream interface for MockStream
func (ms *MockStream) Read(p []byte) (n int, err error) {
	// TODO: Implement deadline checking for Read if possible with io.Reader
	// This is tricky without knowing the underlying type.
	// For simplicity, the mock might ignore read deadlines set via SetReadDeadline
	// unless the reader itself supports it (which io.Reader doesn't guarantee).
	return ms.reader.Read(p)
}

func (ms *MockStream) Write(p []byte) (n int, err error) {
	// --->>> ADDED DETAILED LOGGING <<<---
	writeLogPrefix := fmt.Sprintf("MockStream %s->%s (Write %d bytes):", ms.LocalPeer().ShortString(), ms.RemotePeer().ShortString(), len(p))
	fmt.Printf("%s Attempting underlying write...\n", writeLogPrefix)
	// --->>> END ADDED LOGGING <<<---

	// Directly write using the underlying writer (which might be net.Conn or bufio.Writer)
	n, err = ms.writer.Write(p)

	// --->>> ADDED DETAILED LOGGING <<<---
	if err != nil {
		fmt.Printf("%s Underlying write ERROR: %v\n", writeLogPrefix, err)
	} else {
		fmt.Printf("%s Underlying write SUCCESS (%d bytes written).\n", writeLogPrefix, n)
	}
	// --->>> END ADDED LOGGING <<<---
	// Rely on gob.Encoder or the underlying writer (if buffered) to handle flushing.
	return n, err // Return the result of the underlying write
}

func (ms *MockStream) Close() error {
	// Close the underlying closer (likely the original net.Conn)
	if ms.closer != nil {
		return ms.closer.Close()
	}
	return fmt.Errorf("mockstream closer is nil")
}

func (ms *MockStream) Reset() error {
	ms.cancel() // Cancel context
	// Attempt to close the underlying resource forcefully.
	// If closer is net.Conn, Close() is usually sufficient.
	// If we have the original conn, maybe call Reset specific methods?
	// For simplicity, just Close.
	return ms.Close()
}

func (ms *MockStream) SetDeadline(t time.Time) error {
	ms.deadlineMu.Lock()
	ms.readDeadline = t
	ms.writeDeadline = t
	ms.deadlineMu.Unlock()
	// Attempt to set on underlying conn if available
	if ms.conn != nil {
		return ms.conn.SetDeadline(t)
	}
	// If no conn, maybe try setting on reader/writer if they support it?
	// This gets complex. Let's rely on setting on conn if present.
	return nil
}

func (ms *MockStream) SetReadDeadline(t time.Time) error {
	ms.deadlineMu.Lock()
	ms.readDeadline = t
	ms.deadlineMu.Unlock()
	// Attempt to set on underlying conn if available
	if ms.conn != nil {
		return ms.conn.SetReadDeadline(t)
	}
	// Or try setting on reader if it supports SetReadDeadline
	// if rd, ok := ms.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
	// 	return rd.SetReadDeadline(t)
	// }
	return nil // Indicate success even if underlying doesn't support? Or error?
}

func (ms *MockStream) SetWriteDeadline(t time.Time) error {
	ms.deadlineMu.Lock()
	ms.writeDeadline = t
	ms.deadlineMu.Unlock()
	// Attempt to set on underlying conn if available
	if ms.conn != nil {
		return ms.conn.SetWriteDeadline(t)
	}
	// Or try setting on writer if it supports SetWriteDeadline
	// if wd, ok := ms.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
	// 	return wd.SetWriteDeadline(t)
	// }
	return nil
}

func (ms *MockStream) Protocol() protocol.ID { return ms.protocol }
func (ms *MockStream) Stat() p2pnet.Stats    { return ms.stat } // Ensure qualification
func (ms *MockStream) Conn() p2pnet.Conn     { return nil }     // Simplify: return nil for underlying Conn

// CloseRead closes the read side of the stream.
func (ms *MockStream) CloseRead() error {
	// Try closing the reader if it's an io.Closer
	if rc, ok := ms.reader.(io.Closer); ok {
		return rc.Close()
	}
	// Fallback: Try CloseRead on underlying conn if available
	if connWithCloseRead, ok := ms.conn.(interface{ CloseRead() error }); ok {
		return connWithCloseRead.CloseRead()
	}
	return fmt.Errorf("CloseRead not supported by reader or underlying connection")
}

// CloseWrite closes the write side of the stream.
func (ms *MockStream) CloseWrite() error {
	// Try closing the writer if it's an io.Closer
	if wc, ok := ms.writer.(io.Closer); ok {
		return wc.Close()
	}
	// Fallback: Try CloseWrite on underlying conn if available
	if connWithCloseWrite, ok := ms.conn.(interface{ CloseWrite() error }); ok {
		return connWithCloseWrite.CloseWrite()
	}
	return fmt.Errorf("CloseWrite not supported by writer or underlying connection")
}

// ResetWithError resets the stream with an error code, matching the interface.
func (ms *MockStream) ResetWithError(code p2pnet.StreamErrorCode) error {
	ms.cancel() // Cancel context
	// Attempt to close underlying connection, potentially signaling error
	_ = ms.Close() // Use the main Close method
	return nil
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

// --- MockConn removed as MockStream now uses io.Reader/Writer directly ---

// NewMockHost creates a mock host.
func NewMockHost(t *testing.T, store map[peer.ID]*MockHost) *MockHost {
	// Generate a real private key
	// Use crypto/rand for secure random number generation
	privKey, _, err := p2pcrypto.GenerateKeyPairWithReader(p2pcrypto.RSA, 2048, rand.Reader)
	require.NoError(t, err, "Failed to generate private key")

	// Derive peer ID from public key
	id, err := peer.IDFromPublicKey(privKey.GetPublic())
	require.NoError(t, err, "Failed to derive peer ID from public key")

	listener, err := net.Listen("tcp", "127.0.0.1:0") // Listen on a random port
	require.NoError(t, err)

	h := &MockHost{
		id: id,
		// Store the private key if needed for other operations, e.g., signing
		// privKey: privKey,
		store:          store,
		streamHandlers: make(map[protocol.ID]p2pnet.StreamHandler),
		listener:       listener,
		t:              t,
	}
	// <<< ADDED LOGGING >>>
	t.Logf("NewMockHost: Generated ID %s, Listener %s", id.String(), listener.Addr().String())
	store[id] = h // Register self in the store
	t.Logf("NewMockHost: Registered host %s in store. Store size: %d", id.String(), len(store))
	// <<< END ADDED LOGGING >>>
	// go h.acceptLoop() // Start listening for incoming mock connections - Moved to NewMockRelayNode
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
	mh.t.Logf("MockHost %s: Setting handler for '%s'", mh.id, pid) // Log before setting
	mh.streamHandlers[pid] = handler
	// --- Log map state after setting ---
	keysInMap := make([]protocol.ID, 0, len(mh.streamHandlers))
	for k := range mh.streamHandlers {
		keysInMap = append(keysInMap, k)
	}
	mh.t.Logf("MockHost %s: Handlers map after setting '%s': %v", mh.id, pid, keysInMap)
	// --- End log map state ---
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
	mh.t.Logf("MockHost %s: Starting acceptLoop on %s", mh.id, mh.listener.Addr()) // Log loop start
	for {
		conn, err := mh.listener.Accept()
		if err != nil {
			mh.mu.Lock()
			closed := mh.isClosed
			mh.mu.Unlock()
			if !closed {
				mh.t.Logf("MockHost %s: Accept error on %s: %v", mh.id, mh.listener.Addr(), err) // Log accept error
			} else {
				mh.t.Logf("MockHost %s: Listener closed on %s", mh.id, mh.listener.Addr()) // Log listener closed
			}
			return // Stop loop if listener is closed or error occurs
		}
		// *** UPDATED LOGGING HERE ***
		mh.t.Logf("MockHost %s: Accepted connection from %s on %s", mh.id, conn.RemoteAddr(), mh.listener.Addr())

		// Simulate protocol negotiation - read the protocol ID sent by the initiator
		// In a real scenario, this involves multistream-select.
		// Here, we assume the initiator writes the protocol ID first.
		// *** ADDED LOGGING ***
		mh.t.Logf("MockHost %s: Launching handleIncomingConn goroutine for %s", mh.id, conn.RemoteAddr())
		go mh.handleIncomingConn(conn)
	}
}

// handleIncomingConn reads the protocol ID and routes to the correct handler.
func (mh *MockHost) handleIncomingConn(conn net.Conn) {
	mh.t.Logf("MockHost %s: handleIncomingConn started for %s", mh.id, conn.RemoteAddr())
	// Ensure connection is closed if handler isn't found or an error occurs
	defer func() {
		if r := recover(); r != nil {
			// Log panic and close connection
			mh.t.Logf("MockHost %s: PANIC in handleIncomingConn for %s: %v", mh.id, conn.RemoteAddr(), r)
			conn.Close()
		}
		// Ensure conn is closed if not already handled by handler/error path
		// Check if conn is already closed before trying to close again? Difficult.
		// Let's assume closing multiple times is safe for net.Conn or let handler manage it.
		// conn.Close() // Potentially redundant if handler closes.
	}()

	// --- Simulate Protocol Negotiation (Receiver Side) ---
	// Read protocol ID byte-by-byte until newline, avoiding over-reading
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Deadline for reading protocol ID
	var protocolBytes []byte
	readBuf := make([]byte, 1)
	for {
		n, err := conn.Read(readBuf)
		if err != nil {
			mh.t.Logf("MockHost %s: Failed to read protocol ID byte from %s: %v", mh.id, conn.RemoteAddr(), err)
			conn.Close()
			return
		}
		if n == 1 {
			protocolBytes = append(protocolBytes, readBuf[0])
			if readBuf[0] == '\n' {
				break // Found newline
			}
		}
	}
	conn.SetReadDeadline(time.Time{}) // Clear deadline
	// --- End Protocol Negotiation Simulation ---

	// Trim newline character
	pidStr := string(bytes.TrimSpace(protocolBytes))
	pid := protocol.ID(pidStr)
	mh.t.Logf("MockHost %s: Read protocol ID '%s' from %s", mh.id, pid, conn.RemoteAddr())

	mh.mu.Lock()
	// --- Logging map state ---
	keysInMap := make([]protocol.ID, 0, len(mh.streamHandlers))
	for k := range mh.streamHandlers {
		keysInMap = append(keysInMap, k)
	}
	mh.t.Logf("MockHost %s: Looking for handler for protocol '%s' in handlers: %v", mh.id, pid, keysInMap)
	// --- End logging ---
	handler, ok := mh.streamHandlers[pid]
	mh.mu.Unlock()

	if !ok {
		mh.t.Logf("MockHost %s: No handler found for protocol '%s' from %s", mh.id, pid, conn.RemoteAddr())
		// TODO: In real libp2p, send back a "protocol not supported" message.
		conn.Close()
		return
	}
	mh.t.Logf("MockHost %s: Found handler for protocol '%s' from %s", mh.id, pid, conn.RemoteAddr())

	// *** Create buffered reader/writer HERE ***
	bufReader := bufio.NewReader(conn)
	bufWriter := bufio.NewWriter(conn)

	// Create a mock stream using the buffered reader/writer.
	// The handler will add buffering after the handshake. // <-- Comment outdated, buffering is added here.
	dummyRemoteID, _ := peer.Decode("12D3KooWDummyRemotePeerID") // TODO: Get real remote peer ID if possible? Hard without full handshake.
	ctx, cancel := context.WithCancel(context.Background())
	stat := p2pnet.Stats{}

	// bufWriter := bufio.NewWriter(conn) // Remove: Buffering added by handler // <-- Comment outdated

	mockStream := &MockStream{
		// Pass the raw connection; buffering will be added by the handler if needed // <-- Comment outdated
		reader:     bufReader, // Use buffered reader
		writer:     bufWriter, // Use buffered writer
		closer:     conn,      // Still close the underlying conn
		conn:       conn,      // Keep original conn for Addr, SetDeadline etc.
		protocol:   pid,
		localPeer:  mh.id,
		remotePeer: dummyRemoteID, // Still dummy for incoming, initiator knows real ID
		stat:       stat,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Call the handler with the stream
	mh.t.Logf("MockHost %s: Calling handler for protocol %s from %s", mh.id, pid, conn.RemoteAddr())
	// Run the handler in a separate goroutine to prevent blocking the accept loop?
	// No, the handler itself should manage concurrency if needed. Run synchronously here.
	// go func() {
	//  defer func() {
	//      if r := recover(); r != nil {
	//          mh.t.Logf("MockHost %s: PANIC in handler for protocol %s from %s: %v", mh.id, pid, conn.RemoteAddr(), r)
	//          mockStream.Reset() // Reset stream on handler panic
	//      }
	//  }()
	handler(mockStream)
	mh.t.Logf("MockHost %s: Handler finished for protocol %s from %s", mh.id, pid, conn.RemoteAddr()) // Log when handler returns
	// }() // End goroutine wrapper
}

// NewStream simulates opening a new stream to a remote peer.
// It now simulates protocol negotiation by writing the protocol ID first.
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

	targetAddr := targetHost.listener.Addr().String()
	mh.t.Logf("MockHost %s: Looked up peer %s in store, found host %s listening on %s", mh.id.String(), p.String(), targetHost.ID().String(), targetAddr)
	mh.t.Logf("MockHost %s: Attempting net.Dial to resolved address %s for protocol %s", mh.id.String(), targetAddr, pid)

	// Connect to the target host's listener
	// Use context for dial timeout
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		mh.t.Logf("MockHost %s: Dial failed to %s (%s): %v", mh.id, p, targetAddr, err)
		return nil, fmt.Errorf("failed to dial mock host %s: %w", p, err)
	}
	mh.t.Logf("MockHost %s: Dial successful to %s (%s). LocalAddr: %s, RemoteAddr: %s", mh.id, p, targetAddr, conn.LocalAddr(), conn.RemoteAddr())

	// --- Simulate Protocol Negotiation ---
	// Write the chosen protocol ID, followed by a newline, to the connection.
	// Set a write deadline for negotiation.
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) // Short deadline for protocol write
	_, err = conn.Write([]byte(string(pid) + "\n"))
	conn.SetWriteDeadline(time.Time{}) // Clear deadline
	if err != nil {
		mh.t.Logf("MockHost %s: Failed to write protocol ID '%s' to %s: %v", mh.id, pid, p, err)
		return nil, fmt.Errorf("failed to write protocol ID to mock host %s: %w", p, err)
	}
	mh.t.Logf("MockHost %s: Wrote protocol ID '%s' to %s", mh.id, pid, p)
	// --- End Protocol Negotiation Simulation ---

	// --- Add Handshake for CircuitSetupProtocol ---

	// Wrap the connection in buffered reader/writer

	if pid == protocol.ID(CircuitSetupProtocol) {
		mh.t.Logf("MockHost %s (NewStream to %s): Performing client-side handshake for %s", mh.id, p, pid)
		// Write 0x01
		handshakeBuf := []byte{0x01}
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second)) // Short deadline for handshake write
		_, err = conn.Write(handshakeBuf)
		conn.SetWriteDeadline(time.Time{}) // Clear deadline
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to write handshake byte 0x01 to %s: %w", p, err)
		}

		// Read 0x02
		readBuf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Deadline for reading response
		n, err := conn.Read(readBuf)
		conn.SetReadDeadline(time.Time{}) // Clear deadline
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read handshake byte 0x02 from %s: %w", p, err)
		}
		if n != 1 || readBuf[0] != 0x02 {
			conn.Close()
			return nil, fmt.Errorf("invalid handshake byte 0x02 received from %s: got %v", p, readBuf[:n])
		}
		mh.t.Logf("MockHost %s (NewStream to %s): Handshake complete for %s", mh.id, p, pid)
	}
	// --- End Handshake Logic ---

	bufReader := bufio.NewReader(conn)
	bufWriter := bufio.NewWriter(conn)
	// Create a mock stream. Use buffered I/O.
	streamCtx, streamCancel := context.WithCancel(ctx) // Inherit context
	stat := p2pnet.Stats{}                             // Basic fallback stat

	mockStream := &MockStream{
		// Use buffered reader/writer for stream operations
		reader:     bufReader,
		writer:     bufWriter,
		closer:     conn, // Close the underlying conn
		conn:       conn, // Store conn for Addr, SetDeadline etc.
		protocol:   pid,
		localPeer:  mh.id,
		remotePeer: p,    // We know the remote peer here
		stat:       stat, // Use initialized stat
		ctx:        streamCtx,
		cancel:     streamCancel,
	}

	mh.t.Logf("MockHost %s: MockStream created for %s protocol %s", mh.id, p, pid)
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
	LastActive   time.Time                 // <<< ADD THIS LINE
}

// MockRelayNode holds state for a relay node in the test.
type MockRelayNode struct {
	host         *MockHost
	circuits     map[string]*RelayCircuitState // Map circuitID to state
	circuitsMu   sync.Mutex
	ephemPrivKey []byte         // Relay's ephemeral private key for a specific setup
	ephemPubKey  []byte         // Relay's ephemeral public key for a specific setup
	handlerWg    sync.WaitGroup // NEW: WaitGroup for handler synchronization
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
	h.t.Logf("MockRelayNode %s: Registered handler for %s", h.ID(), protocol.ID(CircuitSetupProtocol)) // Log registration

	h.SetStreamHandler(protocol.ID(CircuitTeardownProtocol), r.handleCircuitTeardownStream)
	h.t.Logf("MockRelayNode %s: Registered handler for %s", h.ID(), protocol.ID(CircuitTeardownProtocol)) // Log registration
	// Start accepting connections only AFTER handlers are set
	r.t.Logf("MockRelayNode %s: Launching acceptLoop goroutine...", h.ID()) // <<< ADDED LOG
	go r.host.acceptLoop()
	return r
}

// handleCircuitSetupStream handles incoming streams for circuit setup/extension/teardown.
// It loops to process multiple messages (Establish, Extend, Teardown) on the same stream.
func (r *MockRelayNode) handleCircuitSetupStream(stream p2pnet.Stream) {
	r.handlerWg.Add(1)       // Indicate handler start
	defer r.handlerWg.Done() // Ensure Done is called when handler exits

	r.t.Logf("Relay %s: Entered handleCircuitSetupStream for stream %s", r.host.ID(), stream.ID())
	// Type assert the stream to our mock implementation to access RemotePeer()
	mockStream, ok := stream.(*MockStream)
	if !ok {
		r.t.Logf("Relay %s: Error: handleCircuitSetupStream received non-MockStream type %T", r.host.ID(), stream)
		stream.Reset()
		return
	}
	remotePeer := mockStream.RemotePeer() // Note: RemotePeer might be dummy
	r.t.Logf("Relay %s: handleCircuitSetupStream started for stream %s from %s", r.host.ID(), stream.ID(), remotePeer)
	defer r.t.Logf("Relay %s: handleCircuitSetupStream finished for stream %s from %s", r.host.ID(), stream.ID(), remotePeer)
	defer stream.Close() // Close stream when handler exits

	// *** Get the underlying writer to Flush later ***
	// We need to flush the bufio.Writer associated with the stream
	bufWriter, ok := stream.(*MockStream).writer.(*bufio.Writer)
	if !ok {
		r.t.Logf("Relay %s: Error: Stream writer is not *bufio.Writer in handleCircuitSetupStream", r.host.ID())
		stream.Reset()
		return
	}

	// --- Server-Side Handshake for CircuitSetupProtocol ---
	// Use the stream's reader/writer directly (which are already buffered)
	r.t.Logf("Relay %s: SetupStream %s: Performing server-side handshake...", r.host.ID(), stream.ID())
	// Read 0x01 from client
	readBuf := make([]byte, 1)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second)) // Deadline for reading handshake
	n, err := stream.Read(readBuf)                          // Reads from stream's bufReader
	stream.SetReadDeadline(time.Time{})                     // Clear deadline
	if err != nil {
		r.t.Logf("Relay %s: SetupStream %s: Failed to read handshake byte 0x01: %v", r.host.ID(), stream.ID(), err)
		stream.Reset()
		return
	}
	if n != 1 || readBuf[0] != 0x01 {
		r.t.Logf("Relay %s: SetupStream %s: Invalid handshake byte received (expected 0x01): got %v", r.host.ID(), stream.ID(), readBuf[:n])
		stream.Reset()
		return
	}

	// Write 0x02 to client
	writeBuf := []byte{0x02}
	stream.SetWriteDeadline(time.Now().Add(2 * time.Second)) // Deadline for writing handshake
	_, err = stream.Write(writeBuf)                          // Writes to stream's bufWriter
	if err == nil {
		err = bufWriter.Flush() // *** FLUSH after handshake write ***
	}
	stream.SetWriteDeadline(time.Time{}) // Clear deadline
	if err != nil {
		r.t.Logf("Relay %s: SetupStream %s: Failed to write/flush handshake byte 0x02: %v", r.host.ID(), stream.ID(), err)
		stream.Reset()
		return
	}
	r.t.Logf("Relay %s: SetupStream %s: Handshake complete.", r.host.ID(), stream.ID())
	// --- End Handshake ---

	// *** Create encoder/decoder directly from stream's reader/writer ***
	decoder := gob.NewDecoder(stream) // Reads from stream's bufReader
	encoder := gob.NewEncoder(stream) // Writes to stream's bufWriter

	for {
		var req CircuitSetupMessage
		r.t.Logf("Relay %s: SetupStream %s: Waiting for next message (before Decode)...", r.host.ID(), stream.ID())
		err := decoder.Decode(&req) // Reads from stream's bufReader
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				r.t.Logf("Relay %s: Setup stream %s closed by remote or EOF", r.host.ID(), stream.ID())
			} else if err.Error() == "gob: duplicate type received" {
				r.t.Logf("Relay %s: Setup stream %s encountered duplicate gob type (likely post-teardown): %v", r.host.ID(), stream.ID(), err)
			} else {
				r.t.Logf("Relay %s: SetupStream %s: Decode error: %v", r.host.ID(), stream.ID(), err)
			}
			return // Exit loop
		}
		// Use stream.RemotePeer() which should be correct now if MockStream stores it properly
		r.t.Logf("Relay %s: Received setup message on stream %s from %s: Type=%d, CircuitID=%s", r.host.ID(), stream.ID(), stream.Conn().RemotePeer(), req.Type, req.CircuitID)
		r.t.Logf("Relay %s: Received setup message NextHopPeerID: [%s]", r.host.ID(), req.NextHopPeerID.String())

		// Pass the stream-based encoder and the bufWriter for flushing
		switch req.Type {
		case TypeEstablish:
			// Pass the stream-based encoder and the bufWriter for flushing
			r.handleEstablish(stream, req, encoder, bufWriter) // Pass bufWriter for flushing
		case TypeExtend:
			// Pass the stream-based encoder and the bufWriter for flushing
			r.handleExtend(stream, req, encoder, bufWriter) // Pass bufWriter for flushing
		case TypeTeardown:
			// Teardown doesn't use encoder/writer in the same way
			r.t.Logf("Relay %s: Received TypeTeardown for circuit %s on stream %s", r.host.ID(), req.CircuitID, stream.ID())
			r.circuitsMu.Lock()
			delete(r.circuits, req.CircuitID)
			r.circuitsMu.Unlock()
			r.t.Logf("Relay %s: Mock state removed for circuit %s", r.host.ID(), req.CircuitID)
			// Send ack? No, teardown is usually fire-and-forget.
			return // Teardown message means we are done with this stream
		default:
			r.t.Logf("Relay %s: Received unknown setup message type: %d on stream %s", r.host.ID(), req.Type, stream.ID())
			resp := CircuitSetupResponse{Type: req.Type, CircuitID: req.CircuitID, Status: StatusError}
			err = encoder.Encode(&resp) // Use stream encoder
			if err == nil {
				err = bufWriter.Flush() // Explicit flush needed now
			}
			if err != nil {
				r.t.Logf("Relay %s: Error sending/flushing error response: %v", r.host.ID(), err)
			}
			stream.Reset()
			return // Exit loop
		}
		r.t.Logf("Relay %s: SetupStream %s: Handled message type %d, looping back to wait for next message...", r.host.ID(), stream.ID(), req.Type)
	}
}

// handleEstablish handles an Establish message.
// It generates ephemeral keys, stores circuit state, and sends a response.
func (r *MockRelayNode) handleEstablish(stream p2pnet.Stream, req CircuitSetupMessage, encoder *gob.Encoder, bufWriter *bufio.Writer) {
	r.t.Logf("Relay %s: Handling Establish for circuit %s from %s", r.host.ID(), req.CircuitID, stream.Conn().RemotePeer())

	// Generate ephemeral keys for this relay hop
	ephemPriv, ephemPub, err := GenerateEphemeralKeyPair() // Correct function name
	if err != nil {
		r.t.Logf("Relay %s: Error generating ephemeral keys: %v", r.host.ID(), err)
		resp := CircuitSetupResponse{Type: TypeEstablish, CircuitID: req.CircuitID, Status: StatusError}
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}
	r.ephemPrivKey = ephemPriv
	r.ephemPubKey = ephemPub

	// Derive shared key with the client's public key (from the request)
	derivedKey, err := DeriveSharedKey(r.ephemPrivKey, req.PublicKey) // Correct function and field name
	if err != nil {
		r.t.Logf("Relay %s: Error deriving shared key: %v", r.host.ID(), err)
		resp := CircuitSetupResponse{Type: TypeEstablish, CircuitID: req.CircuitID, Status: StatusError}
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}
	// Use shared secret to derive symmetric key - Removed, happens in DeriveSharedKey
	// symmetricKey := DeriveSymmetricKey(sharedSecret) // Simplified key derivation

	// Store circuit state
	r.circuitsMu.Lock()
	r.circuits[req.CircuitID] = &RelayCircuitState{
		circuitID:    req.CircuitID,
		incomingPeer: stream.Conn().RemotePeer(), // Peer who sent Establish
		incomingKey:  derivedKey,                 // Use the derived key
		isExit:       req.NextHopPeerID == "",    // Exit if no next hop specified
		LastActive:   time.Now(),                 // <<< UPDATE LAST ACTIVE
	}
	r.circuitsMu.Unlock()
	r.t.Logf("Relay %s: Stored state for circuit %s (IsExit: %v)", r.host.ID(), req.CircuitID, r.circuits[req.CircuitID].isExit)

	// Send response
	resp := CircuitSetupResponse{
		Type:      TypeEstablished, // Correct response type
		CircuitID: req.CircuitID,
		Status:    StatusOK,
		PublicKey: r.ephemPubKey, // Correct field name
		// DerivedKeyHash: HashKey(symmetricKey), // Removed field
	}
	// Correct log message format
	r.t.Logf("Relay %s: Sending Establish response for circuit %s (Status: %d, PubKeyLen: %d)", r.host.ID(), req.CircuitID, resp.Status, len(resp.PublicKey))
	err = encoder.Encode(&resp)
	if err == nil {
		err = bufWriter.Flush() // Flush after encode
	}
	if err != nil {
		r.t.Logf("Relay %s: Error sending/flushing Establish response: %v", r.host.ID(), err)
		// Clean up state?
		r.circuitsMu.Lock()
		delete(r.circuits, req.CircuitID)
		r.circuitsMu.Unlock()
	} else {
		r.t.Logf("Relay %s: Successfully sent/flushed Establish response for circuit %s", r.host.ID(), req.CircuitID)
	}
}

// handleExtend handles an Extend message.
// It decrypts the next hop info, forwards the Extend request, stores state, and relays the response.
func (r *MockRelayNode) handleExtend(stream p2pnet.Stream, req CircuitSetupMessage, encoder *gob.Encoder, bufWriter *bufio.Writer) {
	r.t.Logf("Relay %s: Handling Extend for circuit %s from %s to %s", r.host.ID(), req.CircuitID, stream.Conn().RemotePeer(), req.NextHopPeerID)

	r.circuitsMu.Lock()
	state, ok := r.circuits[req.CircuitID]
	if !ok {
		r.circuitsMu.Unlock()
		r.t.Logf("Relay %s: Error: Circuit state not found for Extend request %s", r.host.ID(), req.CircuitID)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError} // Use TypeExtended for response
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}
	state.LastActive = time.Now() // <<< UPDATE LAST ACTIVE
	incomingKey := state.incomingKey
	r.circuitsMu.Unlock()

	// Decrypt the encrypted next hop data using the incoming key
	// Assuming the encrypted data (intended for the next hop) is in req.PublicKey
	nextHopReqBytes, err := DecryptPayload(req.PublicKey, incomingKey) // Correct function and field name
	if err != nil {
		r.t.Logf("Relay %s: Error decrypting next hop data for circuit %s: %v", r.host.ID(), req.CircuitID, err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError} // Use TypeExtended for response
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}

	var nextHopReq CircuitSetupMessage
	dec := gob.NewDecoder(bytes.NewReader(nextHopReqBytes))
	err = dec.Decode(&nextHopReq)
	if err != nil {
		r.t.Logf("Relay %s: Error decoding decrypted next hop request for circuit %s: %v", r.host.ID(), req.CircuitID, err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError} // Use TypeExtended for response
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}
	// Log the *inner* request's details
	r.t.Logf("Relay %s: Decrypted next hop request for circuit %s: Type=%d, NextHop=%s, NextNextHop=%s", r.host.ID(), req.CircuitID, nextHopReq.Type, nextHopReq.NextHopPeerID, nextHopReq.NextNextHopPeerID)

	// Open a new stream to the next hop
	nextHopPeerID := req.NextHopPeerID // Use the ID from the *outer* request
	r.t.Logf("Relay %s: Opening setup stream to next hop %s for circuit %s", r.host.ID(), nextHopPeerID, req.CircuitID)
	nextHopStream, err := r.host.NewStream(context.Background(), nextHopPeerID, protocol.ID(CircuitSetupProtocol))
	if err != nil {
		r.t.Logf("Relay %s: Error opening stream to next hop %s: %v", r.host.ID(), nextHopPeerID, err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError} // Use TypeExtended for response
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}
	defer nextHopStream.Close()
	r.t.Logf("Relay %s: Opened setup stream %s to next hop %s", r.host.ID(), nextHopStream.ID(), nextHopPeerID)

	// Create encoder/decoder for the next hop stream
	nextHopBufReader := bufio.NewReader(nextHopStream)
	nextHopBufWriter := bufio.NewWriter(nextHopStream)
	nextHopEncoder := gob.NewEncoder(nextHopBufWriter)
	nextHopDecoder := gob.NewDecoder(nextHopBufReader)

	// Forward the decrypted request (nextHopReq) to the next hop
	r.t.Logf("Relay %s: Forwarding %d request to %s for circuit %s", r.host.ID(), nextHopReq.Type, nextHopPeerID, req.CircuitID) // Log type correctly
	err = nextHopEncoder.Encode(&nextHopReq)
	if err == nil {
		err = nextHopBufWriter.Flush() // Flush after encode
	}
	if err != nil {
		r.t.Logf("Relay %s: Error sending/flushing request to next hop %s: %v", r.host.ID(), nextHopPeerID, err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError} // Use TypeExtended for response
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}
	r.t.Logf("Relay %s: Successfully sent/flushed request to next hop %s", r.host.ID(), nextHopPeerID)

	// Wait for the response from the next hop
	var nextHopResp CircuitSetupResponse
	r.t.Logf("Relay %s: Waiting for response from next hop %s on stream %s...", r.host.ID(), nextHopPeerID, nextHopStream.ID())
	err = nextHopDecoder.Decode(&nextHopResp)
	if err != nil {
		r.t.Logf("Relay %s: Error decoding response from next hop %s: %v", r.host.ID(), nextHopPeerID, err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError} // Use TypeExtended for response
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}
	// Correct log format: Use PublicKey, remove DerivedKeyHash
	r.t.Logf("Relay %s: Received response from next hop %s: Status=%d, PubKeyLen=%d", r.host.ID(), nextHopPeerID, nextHopResp.Status, len(nextHopResp.PublicKey))

	// If the next hop succeeded, update our state
	if nextHopResp.Status == StatusOK {
		r.circuitsMu.Lock()
		if state, ok := r.circuits[req.CircuitID]; ok {
			state.outgoingPeer = nextHopPeerID
			// The outgoingKey is derived by the *client* and used for encryption layers.
			// The relay doesn't store it directly in this simplified model,
			// but it needs the incomingKey to decrypt/encrypt messages relayed back.
			// Update exit status based on the *inner* forwarded request (nextHopReq)
			state.isExit = (nextHopReq.NextHopPeerID == "")
			r.t.Logf("Relay %s: Updated state for circuit %s: OutgoingPeer=%s, IsExit=%v", r.host.ID(), req.CircuitID, nextHopPeerID, state.isExit)
		} else {
			// State might have been removed by concurrent teardown? Log warning.
			r.t.Logf("Relay %s: WARNING: Circuit state %s disappeared during Extend handling", r.host.ID(), req.CircuitID)
		}
		r.circuitsMu.Unlock()
	}

	// Encrypt the response from the next hop using the incoming key
	respBytes, err := gobEncodeToBytes(&nextHopResp)
	if err != nil {
		r.t.Logf("Relay %s: Error encoding next hop response for encryption: %v", r.host.ID(), err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError} // Use TypeExtended for response
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}

	encryptedResp, err := EncryptPayload(respBytes, incomingKey) // Correct function name
	if err != nil {
		r.t.Logf("Relay %s: Error encrypting next hop response: %v", r.host.ID(), err)
		resp := CircuitSetupResponse{Type: TypeExtended, CircuitID: req.CircuitID, Status: StatusError} // Use TypeExtended for response
		_ = encoder.Encode(&resp)
		_ = bufWriter.Flush() // Flush after encode
		return
	}

	// Send the encrypted response back to the previous hop/client
	// Place encrypted data in PublicKey field
	finalResp := CircuitSetupResponse{
		Type:      TypeExtended, // Correct response type
		CircuitID: req.CircuitID,
		Status:    nextHopResp.Status, // Relay the status from the next hop
		PublicKey: encryptedResp,      // Put encrypted response here
		// DerivedKeyHash: nextHopResp.DerivedKeyHash, // Removed field
	}
	// Correct log format: Use PublicKey, remove DerivedKeyHash
	r.t.Logf("Relay %s: Sending encrypted Extend response back for circuit %s (Status: %d, EncryptedLen: %d)", r.host.ID(), req.CircuitID, finalResp.Status, len(finalResp.PublicKey))
	err = encoder.Encode(&finalResp)
	if err == nil {
		err = bufWriter.Flush() // Flush after encode
	}
	if err != nil {
		r.t.Logf("Relay %s: Error sending/flushing encrypted Extend response: %v", r.host.ID(), err)
	} else {
		r.t.Logf("Relay %s: Successfully sent/flushed encrypted Extend response for circuit %s", r.host.ID(), req.CircuitID)
	}
}

// handleTeardown handles a Teardown message (simplified).
func (r *MockRelayNode) handleTeardown(stream p2pnet.Stream, req CircuitSetupMessage) {
	r.t.Logf("Relay %s: Handling Teardown for circuit %s from %s", r.host.ID(), req.CircuitID, stream.Conn().RemotePeer())

	r.circuitsMu.Lock()
	state, ok := r.circuits[req.CircuitID]
	if !ok {
		r.circuitsMu.Unlock()
		r.t.Logf("Relay %s: Teardown received for unknown circuit %s", r.host.ID(), req.CircuitID)
		return // Ignore if circuit doesn't exist
	}
	outgoingPeer := state.outgoingPeer
	isExit := state.isExit
	delete(r.circuits, req.CircuitID)
	r.circuitsMu.Unlock()
	r.t.Logf("Relay %s: Removed state for circuit %s", r.host.ID(), req.CircuitID)

	// If not an exit node, forward the teardown message
	if !isExit && outgoingPeer != "" {
		r.t.Logf("Relay %s: Forwarding Teardown for circuit %s to %s", r.host.ID(), req.CircuitID, outgoingPeer)
		// Open teardown stream
		teardownStream, err := r.host.NewStream(context.Background(), outgoingPeer, protocol.ID(CircuitTeardownProtocol))
		if err != nil {
			r.t.Logf("Relay %s: Error opening teardown stream to %s: %v", r.host.ID(), outgoingPeer, err)
			return // Can't forward
		}
		defer teardownStream.Close()

		// Send teardown message (just the circuit ID is needed)
		teardownMsg := CircuitTeardownMessage{CircuitID: req.CircuitID}
		enc := gob.NewEncoder(teardownStream) // Use teardown stream directly
		err = enc.Encode(&teardownMsg)
		// Flush if using buffered writer (not needed if writing directly to stream)
		// if err == nil {
		// 	if bw, ok := teardownStream.(*MockStream).writer.(*bufio.Writer); ok {
		// 		err = bw.Flush()
		// 	}
		// }
		if err != nil {
			r.t.Logf("Relay %s: Error sending teardown message to %s: %v", r.host.ID(), outgoingPeer, err)
		} else {
			r.t.Logf("Relay %s: Teardown message sent to %s", r.host.ID(), outgoingPeer)
		}
	} else {
		r.t.Logf("Relay %s: Teardown complete for exit circuit %s", r.host.ID(), req.CircuitID)
	}
}

// handleRelayStream handles incoming data streams for relaying.
// This is a placeholder and needs implementation based on the relay protocol.
func (r *MockRelayNode) handleRelayStream(stream p2pnet.Stream) {
	r.t.Logf("Relay %s: handleRelayStream started for stream %s from %s", r.host.ID(), stream.ID(), stream.Conn().RemotePeer())
	defer r.t.Logf("Relay %s: handleRelayStream finished for stream %s from %s", r.host.ID(), stream.ID(), stream.Conn().RemotePeer())
	defer stream.Close()

	// 1. Read the initial message to identify the circuit ID.
	//    This might involve decryption depending on the protocol.
	// 2. Look up the circuit state (incoming/outgoing peers and keys).
	// 3. If exit node: Decrypt data and send to target (not implemented here).
	// 4. If relay node:
	//    a. Find/open stream to the next hop (outgoingPeer).
	//    b. Decrypt data from incoming stream using incomingKey.
	//    c. Re-encrypt data for the next hop using outgoingKey (derived by client).
	//    d. Write encrypted data to the outgoing stream.
	//    e. Read response from outgoing stream, decrypt with outgoingKey, encrypt with incomingKey, write back to incoming stream.
	//    f. Manage stream lifecycles.

	// --- Simplified Placeholder ---
	// Assume first message contains circuit ID (unencrypted for mock)
	decoder := gob.NewDecoder(stream)
	var initialMsg struct {
		CircuitID string
		Payload   []byte
	}
	err := decoder.Decode(&initialMsg)
	if err != nil {
		r.t.Logf("Relay %s: Error decoding initial relay message on stream %s: %v", r.host.ID(), stream.ID(), err)
		stream.Reset()
		return
	}
	r.t.Logf("Relay %s: Received initial relay message for circuit %s on stream %s", r.host.ID(), initialMsg.CircuitID, stream.ID())

	r.circuitsMu.Lock()
	state, ok := r.circuits[initialMsg.CircuitID]
	if !ok {
		r.circuitsMu.Unlock()
		r.t.Logf("Relay %s: Relay request for unknown circuit %s on stream %s", r.host.ID(), initialMsg.CircuitID, stream.ID())
		stream.Reset()
		return
	}
	state.LastActive = time.Now() // <<< UPDATE LAST ACTIVE
	// Store the stream associated with the incoming peer for this circuit?
	if state.dataStreams == nil {
		state.dataStreams = make(map[peer.ID]p2pnet.Stream)
	}
	state.dataStreams[stream.Conn().RemotePeer()] = stream // Associate stream with incoming peer
	r.t.Logf("Relay %s: Associated data stream %s with incoming peer %s for circuit %s", r.host.ID(), stream.ID(), stream.Conn().RemotePeer(), initialMsg.CircuitID)
	r.circuitsMu.Unlock()

	// Placeholder: Just echo back a confirmation (unencrypted)
	encoder := gob.NewEncoder(stream)
	respMsg := struct {
		CircuitID string
		Status    string
	}{
		CircuitID: initialMsg.CircuitID,
		Status:    "Relay Received (Mock)",
	}
	err = encoder.Encode(&respMsg)
	if err != nil {
		r.t.Logf("Relay %s: Error sending mock relay confirmation for circuit %s: %v", r.host.ID(), initialMsg.CircuitID, err)
	} else {
		r.t.Logf("Relay %s: Sent mock relay confirmation for circuit %s", r.host.ID(), initialMsg.CircuitID)
	}

	// Keep stream open to simulate relaying? Or close after one message?
	// For now, keep open but do nothing else.
	<-context.Background().Done() // Wait until stream is closed or reset (Note: Using Background context here)
}

// handleCircuitTeardownStream handles incoming teardown requests.
func (r *MockRelayNode) handleCircuitTeardownStream(stream p2pnet.Stream) {
	r.t.Logf("Relay %s: handleCircuitTeardownStream started for stream %s from %s", r.host.ID(), stream.ID(), stream.Conn().RemotePeer())
	defer r.t.Logf("Relay %s: handleCircuitTeardownStream finished for stream %s from %s", r.host.ID(), stream.ID(), stream.Conn().RemotePeer())
	defer stream.Close()

	decoder := gob.NewDecoder(stream)
	var msg CircuitTeardownMessage
	err := decoder.Decode(&msg)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			r.t.Logf("Relay %s: Teardown stream %s closed by remote or EOF", r.host.ID(), stream.ID())
		} else {
			r.t.Logf("Relay %s: Error decoding teardown message on stream %s: %v", r.host.ID(), stream.ID(), err)
		}
		stream.Reset()
		return
	}

	r.t.Logf("Relay %s: Received teardown message for circuit %s via dedicated stream %s", r.host.ID(), msg.CircuitID, stream.ID())

	// Use the same teardown logic as handleTeardown
	r.circuitsMu.Lock()
	state, ok := r.circuits[msg.CircuitID]
	if !ok {
		r.circuitsMu.Unlock()
		r.t.Logf("Relay %s: Teardown (stream) received for unknown circuit %s", r.host.ID(), msg.CircuitID)
		return // Ignore if circuit doesn't exist
	}
	outgoingPeer := state.outgoingPeer
	isExit := state.isExit
	delete(r.circuits, msg.CircuitID)
	r.circuitsMu.Unlock()
	r.t.Logf("Relay %s: Removed state for circuit %s (via stream)", r.host.ID(), msg.CircuitID)

	// If not an exit node, forward the teardown message using the dedicated protocol
	if !isExit && outgoingPeer != "" {
		r.t.Logf("Relay %s: Forwarding Teardown (stream) for circuit %s to %s", r.host.ID(), msg.CircuitID, outgoingPeer)
		teardownStream, err := r.host.NewStream(context.Background(), outgoingPeer, protocol.ID(CircuitTeardownProtocol))
		if err != nil {
			r.t.Logf("Relay %s: Error opening teardown stream to %s: %v", r.host.ID(), outgoingPeer, err)
			return // Can't forward
		}
		defer teardownStream.Close()

		// Send teardown message
		forwardMsg := CircuitTeardownMessage{CircuitID: msg.CircuitID}
		enc := gob.NewEncoder(teardownStream)
		err = enc.Encode(&forwardMsg)
		// Flush? Not needed if writing directly to stream/conn.
		if err != nil {
			r.t.Logf("Relay %s: Error sending teardown message to %s: %v", r.host.ID(), outgoingPeer, err)
		} else {
			r.t.Logf("Relay %s: Teardown message sent to %s (via stream)", r.host.ID(), outgoingPeer)
		}
	} else {
		r.t.Logf("Relay %s: Teardown complete for exit circuit %s (via stream)", r.host.ID(), msg.CircuitID)
	}
}

// --- Test Cases ---

// TestClientCircuitBuilder_BuildCircuit_Success_MultiHop tests building a 3-hop circuit successfully.
func TestClientCircuitBuilder_BuildCircuit_Success_MultiHop(t *testing.T) {
	// Setup mock network
	mockStore := make(map[peer.ID]*MockHost)
	relay1 := NewMockRelayNode(t, mockStore)
	relay2 := NewMockRelayNode(t, mockStore)
	relay3 := NewMockRelayNode(t, mockStore) // Exit node
	clientHost := NewMockHost(t, mockStore)

	// Ensure all hosts are closed at the end
	defer clientHost.Close()
	defer relay1.host.Close()
	defer relay2.host.Close()
	defer relay3.host.Close()

	// Wait for listeners to be ready (simple approach)
	t.Logf("Waiting for listeners to start...")
	time.Sleep(100 * time.Millisecond) // Give listeners time to start accepting
	t.Logf("Listeners should be ready, now building circuit...")

	// Create circuit builder
	builder, err := NewCircuitBuilder(clientHost) // Use correct function name, handle error
	require.NoError(t, err)

	// Define circuit path
	path := []peer.ID{relay1.host.ID(), relay2.host.ID(), relay3.host.ID()}

	// Build the circuit
	circuit, err := builder.BuildCircuit(context.Background(), path)

	// Assertions
	require.NoError(t, err, "BuildCircuit should succeed")
	require.NotNil(t, circuit, "Circuit should not be nil")
	assert.Equal(t, 3, len(circuit.Path), "Circuit should have 3 hops") // Use Path
	assert.Equal(t, path[0], circuit.Path[0], "Hop 1 peer ID mismatch") // Use Path
	assert.Equal(t, path[1], circuit.Path[1], "Hop 2 peer ID mismatch") // Use Path
	assert.Equal(t, path[2], circuit.Path[2], "Hop 3 peer ID mismatch") // Use Path
	assert.Equal(t, path[2], circuit.ExitNode, "Exit node ID mismatch") // Use ExitNode
	assert.NotEmpty(t, circuit.ID, "Circuit ID should not be empty")    // Use ID

	// Check relay states (optional, for deeper verification)
	relay1.circuitsMu.Lock()
	state1, ok1 := relay1.circuits[circuit.ID] // Use ID
	relay1.circuitsMu.Unlock()
	assert.True(t, ok1, "Relay 1 should have state for the circuit")
	assert.Equal(t, clientHost.ID(), state1.incomingPeer, "Relay 1 incoming peer mismatch")
	assert.Equal(t, relay2.host.ID(), state1.outgoingPeer, "Relay 1 outgoing peer mismatch")
	assert.False(t, state1.isExit, "Relay 1 should not be exit")

	relay2.circuitsMu.Lock()
	state2, ok2 := relay2.circuits[circuit.ID] // Use ID
	relay2.circuitsMu.Unlock()
	assert.True(t, ok2, "Relay 2 should have state for the circuit")
	assert.Equal(t, relay1.host.ID(), state2.incomingPeer, "Relay 2 incoming peer mismatch")
	assert.Equal(t, relay3.host.ID(), state2.outgoingPeer, "Relay 2 outgoing peer mismatch")
	assert.False(t, state2.isExit, "Relay 2 should not be exit")

	relay3.circuitsMu.Lock()
	state3, ok3 := relay3.circuits[circuit.ID] // Use ID
	relay3.circuitsMu.Unlock()
	assert.True(t, ok3, "Relay 3 should have state for the circuit")
	assert.Equal(t, relay2.host.ID(), state3.incomingPeer, "Relay 3 incoming peer mismatch")
	assert.Equal(t, peer.ID(""), state3.outgoingPeer, "Relay 3 outgoing peer should be empty")
	assert.True(t, state3.isExit, "Relay 3 should be exit")

	// Teardown the circuit
	err = circuit.Close() // Use Close()
	assert.NoError(t, err, "Close should succeed")

	// Allow time for teardown messages to propagate in mock network
	time.Sleep(50 * time.Millisecond)

	// Verify state is cleaned up
	relay1.circuitsMu.Lock()
	_, ok1_after := relay1.circuits[circuit.ID] // Use ID
	relay1.circuitsMu.Unlock()
	assert.False(t, ok1_after, "Relay 1 state should be cleaned up after teardown")

	relay2.circuitsMu.Lock()
	_, ok2_after := relay2.circuits[circuit.ID] // Use ID
	relay2.circuitsMu.Unlock()
	assert.False(t, ok2_after, "Relay 2 state should be cleaned up after teardown")

	relay3.circuitsMu.Lock()
	_, ok3_after := relay3.circuits[circuit.ID] // Use ID
	relay3.circuitsMu.Unlock()
	assert.False(t, ok3_after, "Relay 3 state should be cleaned up after teardown")

	// Wait for handlers to finish to avoid race detector issues
	relay1.handlerWg.Wait()
	relay2.handlerWg.Wait()
	relay3.handlerWg.Wait()
}

// TestClientCircuit_SendData_Success tests sending data through an established circuit.
func TestClientCircuit_SendData_Success(t *testing.T) {
	// Setup mock network
	mockStore := make(map[peer.ID]*MockHost)
	relay1 := NewMockRelayNode(t, mockStore)
	relay2 := NewMockRelayNode(t, mockStore)
	relay3 := NewMockRelayNode(t, mockStore) // Exit node
	clientHost := NewMockHost(t, mockStore)
	targetServiceHost := NewMockHost(t, mockStore) // Simulate the final destination service

	// Ensure all hosts are closed at the end
	defer clientHost.Close()
	defer relay1.host.Close()
	defer relay2.host.Close()
	defer relay3.host.Close()
	defer targetServiceHost.Close()

	// Wait for listeners
	time.Sleep(100 * time.Millisecond)

	// --- Setup Target Service Handler ---
	targetProtocol := protocol.ID("/test/target/1.0.0")
	receivedDataChan := make(chan []byte, 1)
	targetServiceHost.SetStreamHandler(targetProtocol, func(stream p2pnet.Stream) {
		t.Logf("Target Service %s: Received stream %s from %s", targetServiceHost.ID(), stream.ID(), stream.Conn().RemotePeer())
		defer stream.Close()
		// Simulate reading data (e.g., HTTP request)
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("Target Service: Error reading from stream: %v", err)
			return
		}
		t.Logf("Target Service %s: Read %d bytes: %s", targetServiceHost.ID(), n, string(buf[:n]))
		receivedDataChan <- buf[:n] // Send received data back to test

		// Simulate sending a response
		_, err = stream.Write([]byte("Service Response Data"))
		if err != nil {
			t.Errorf("Target Service: Error writing response: %v", err)
		}
		t.Logf("Target Service %s: Sent response", targetServiceHost.ID())
	})
	// --- End Target Service Handler ---

	// --- Setup Exit Node Relay Handler ---
	// The exit node needs a handler for the RelayProtocol to forward data
	// to the actual target service.
	relay3.host.SetStreamHandler(protocol.ID(RelayProtocol), func(stream p2pnet.Stream) {
		r := relay3                                                                                                                    // Capture relay3 as r
		t.Logf("Exit Node %s (Relay Handler): Received relay stream %s from %s", r.host.ID(), stream.ID(), stream.Conn().RemotePeer()) // Use r and Conn()
		defer stream.Close()

		// 1. Decode the initial relay message (contains target info + first data chunk)
		decoder := gob.NewDecoder(stream)
		var onionPkt OnionPacket // Use OnionPacket instead of RelayMessage
		err := decoder.Decode(&onionPkt)
		if err != nil {
			t.Errorf("Exit Node %s: Error decoding onion packet: %v", r.host.ID(), err) // Use r
			stream.Reset()
			return
		}
		// Assuming OnionPacket has CircuitID and EncryptedPayload fields.
		// Logging might need adjustment based on OnionPacket structure.
		t.Logf("Exit Node %s: Decoded onion packet for circuit %s", r.host.ID(), onionPkt.CircuitID) // Use r and onionPkt

		// 2. Decrypt the payload (using the key shared with the previous hop)
		r.circuitsMu.Lock()                         // Use r
		state, ok := r.circuits[onionPkt.CircuitID] // Use r and onionPkt
		if !ok {
			r.circuitsMu.Unlock()                                                                                  // Use r
			t.Errorf("Exit Node %s: Circuit state not found for onion packet %s", r.host.ID(), onionPkt.CircuitID) // Use r and onionPkt
			stream.Reset()
			return
		}
		incomingKey := state.incomingKey
		r.circuitsMu.Unlock() // Use r

		// DecryptPayload expects LayeredPayload or InnerPayload structure
		// Let's assume for the exit node, it's the InnerPayload directly encrypted
		// If CreateOnionLayers wraps even the last hop, this needs adjustment
		decryptedPayload, err := DecryptPayload(onionPkt.EncryptedPayload, incomingKey) // Use DecryptPayload and onionPkt
		if err != nil {
			t.Errorf("Exit Node %s: Error decrypting payload: %v", r.host.ID(), err) // Use r
			stream.Reset()
			return
		}
		t.Logf("Exit Node %s: Decrypted payload (%d bytes)", r.host.ID(), len(decryptedPayload)) // Use r

		// --- Decode InnerPayload ---
		var innerPayload InnerPayload
		err = gob.NewDecoder(bytes.NewReader(decryptedPayload)).Decode(&innerPayload)
		if err != nil {
			// It's possible the decrypted payload IS the final data, not InnerPayload struct
			// For now, assume it must be InnerPayload based on previous logic
			t.Errorf("Exit Node %s: Failed to decode InnerPayload: %v", r.host.ID(), err) // Use r
			stream.Reset()
			return
		}
		t.Logf("Exit Node %s: Decoded InnerPayload: Target=%s, DataLen=%d", r.host.ID(), innerPayload.FinalRecipient, len(innerPayload.Data)) // Use r and FinalRecipient

		// 3. Open a stream to the actual target service
		targetStream, err := r.host.NewStream(context.Background(), innerPayload.FinalRecipient, protocol.ID(TargetServiceProtocol)) // Use r, FinalRecipient, and defined TargetServiceProtocol
		if err != nil {
			t.Errorf("Exit Node %s: Failed to open stream to target service %s: %v", r.host.ID(), innerPayload.FinalRecipient, err) // Use r and FinalRecipient
			// TODO: Send error back through circuit?
			stream.Reset()
			return
		}
		defer targetStream.Close()
		t.Logf("Exit Node %s: Opened stream %s to target service %s", r.host.ID(), targetStream.ID(), innerPayload.FinalRecipient) // Use r and FinalRecipient

		// 4. Write the inner payload's data to the target service stream
		_, err = targetStream.Write(innerPayload.Data) // Use innerPayload.Data
		if err != nil {
			t.Errorf("Exit Node %s: Failed to write payload to target service: %v", r.host.ID(), err) // Use r
			stream.Reset()                                                                            // Signal error back?
			return
		}
		// Close the write side to signal end of request data to target
		if err := targetStream.CloseWrite(); err != nil {
			t.Logf("Exit Node %s: Error closing write to target stream: %v", r.host.ID(), err) // Use r
		}
		t.Logf("Exit Node %s: Wrote payload to target service stream %s", r.host.ID(), targetStream.ID()) // Use r

		// 5. Read the response from the target service stream
		targetResponse, err := io.ReadAll(targetStream) // Read until target closes or EOF
		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("Exit Node %s: Failed to read response from target service: %v", r.host.ID(), err) // Use r
			stream.Reset()
			return
		}
		t.Logf("Exit Node %s: Read response from target service (%d bytes)", r.host.ID(), len(targetResponse)) // Use r

		// 6. Encrypt the response using the incoming key
		//    The response needs to be wrapped appropriately for the return trip.
		//    For simplicity here, just encrypt the raw response.
		//    A real implementation might need a response structure.
		encryptedResponse, err := EncryptPayload(targetResponse, incomingKey) // Use EncryptPayload
		if err != nil {
			t.Errorf("Exit Node %s: Failed to encrypt target response: %v", r.host.ID(), err) // Use r
			stream.Reset()
			return
		}
		t.Logf("Exit Node %s: Encrypted target response (%d bytes)", r.host.ID(), len(encryptedResponse)) // Use r

		// 7. Send the encrypted response back through the incoming relay stream
		//    Use OnionPacket structure for the response
		responsePkt := OnionPacket{ // Use OnionPacket
			CircuitID:        onionPkt.CircuitID, // Use onionPkt
			EncryptedPayload: encryptedResponse,  // Send encrypted response back
		}
		encoder := gob.NewEncoder(stream)
		err = encoder.Encode(&responsePkt) // Use responsePkt
		if err != nil {
			t.Errorf("Exit Node %s: Failed to send encrypted response back: %v", r.host.ID(), err) // Use r
		} else {
			t.Logf("Exit Node %s: Sent encrypted response back on stream %s", r.host.ID(), stream.ID()) // Use r
		}
	})
	// --- End Exit Node Relay Handler ---

	// Build the circuit first
	builder, err := NewCircuitBuilder(clientHost) // Use correct function name, handle error
	require.NoError(t, err)
	path := []peer.ID{relay1.host.ID(), relay2.host.ID(), relay3.host.ID()}
	circuit, err := builder.BuildCircuit(context.Background(), path)
	require.NoError(t, err)
	require.NotNil(t, circuit)
	defer circuit.Close() // Ensure teardown using Close()

	// Data to send
	testData := []byte("Hello Onion Network!")

	// Send data through the circuit
	targetAddrInfo := peer.AddrInfo{ID: targetServiceHost.ID()} // Mock: Just need ID
	// Send data through the circuit - NOTE:```go
	// Send data through the circuit - NOTE: Current SendData doesn't handle responses.
	err = circuit.SendData(context.Background(), targetAddrInfo.ID, testData)
	require.NoError(t, err, "SendData should not return an immediate error")

	// TODO: Implement response handling in SendData or a separate ReceiveData method
	// For now, we only verify that the target service received the data.

	// Verify data received by target service
	select {
	case receivedData := <-receivedDataChan:
		assert.Equal(t, testData, receivedData, "Data received by target service mismatch")
		t.Logf("Test: Verified target service received correct data.")
	case <-time.After(1 * time.Second):
		t.Fatal("Test: Timed out waiting for target service to confirm data reception")
	}

	// Wait for handlers to finish
	relay1.handlerWg.Wait()
	relay2.handlerWg.Wait()
	relay3.handlerWg.Wait()
}

// --- Helper Functions ---

// gobEncodeToBytes encodes an interface{} into a byte slice using gob.
func gobEncodeToBytes(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
