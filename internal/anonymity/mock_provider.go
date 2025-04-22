package anonymity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync" // Needed for mutex

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// MockConnection implements the Connection interface for testing.
// (Keep MockConnection and MockListener definitions as they were before)
type MockConnection struct {
	io.Reader
	io.Writer
	io.Closer
	Local  net.Addr
	Remote net.Addr
}
type MockListener struct {
	addr    multiaddr.Multiaddr
	acceptQ chan Connection
	closeCh chan struct{}
	mu      sync.Mutex // Protect close state
	closed  bool
}

func NewMockListener(addr multiaddr.Multiaddr) *MockListener {
	return &MockListener{
		addr:    addr,
		acceptQ: make(chan Connection, 1),
		closeCh: make(chan struct{}),
	}
}
func (m *MockListener) Accept() (Connection, error) {
	select {
	case conn, ok := <-m.acceptQ:
		if !ok {
			return nil, errors.New("mock listener closed")
		}
		return conn, nil
	case <-m.closeCh:
		return nil, errors.New("mock listener closed")
	}
}
func (m *MockListener) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("already closed")
	}
	m.closed = true
	close(m.closeCh)
	// Closing acceptQ signals Accept() to stop, but might drop injected connections
	// Drain it first? Or just close is fine for simple tests. Let's just close.
	close(m.acceptQ)
	return nil
}
func (m *MockListener) Addr() multiaddr.Multiaddr {
	return m.addr
}
func (m *MockListener) InjectConnection(conn Connection) bool {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return false
	}
	// Non-blocking send
	select {
	case m.acceptQ <- conn:
		return true
	default: // Buffer full or closed by race
		return false
	}
}

// MockAnonymityProvider implements the AnonymityProvider interface for testing.
type MockAnonymityProvider struct {
	FailDial           bool
	FailListen         bool
	Listener           *MockListener          // Store the listener created by ListenAnonymously
	DialedPeers        map[peer.ID]Connection // Track Dial attempts
	expectedListenAddr multiaddr.Multiaddr    // Configurable address for ListenAnonymously
	mu                 sync.Mutex             // Protect access to Listener/DialedPeers
}

// NewMockAnonymityProvider creates a new mock provider.
// Optionally takes an address to be returned by the mock listener.
func NewMockAnonymityProvider(listenAddr ...multiaddr.Multiaddr) *MockAnonymityProvider {
	m := &MockAnonymityProvider{
		DialedPeers: make(map[peer.ID]Connection),
	}
	if len(listenAddr) > 0 && listenAddr[0] != nil {
		m.expectedListenAddr = listenAddr[0]
	}
	return m
}

// SetExpectedListenAddr allows tests to set the address the mock listener should use.
func (m *MockAnonymityProvider) SetExpectedListenAddr(addr multiaddr.Multiaddr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expectedListenAddr = addr
}

func (m *MockAnonymityProvider) DialPeerAnonymously(ctx context.Context, p peer.ID) (Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailDial {
		return nil, errors.New("mock dial failed")
	}
	// Use net.Pipe for a more realistic connection simulation
	clientConn, serverConn := net.Pipe()

	mockConn := &MockConnection{
		Reader: clientConn, // Use pipe ends
		Writer: clientConn,
		Closer: clientConn,
		Local:  clientConn.LocalAddr(),
		Remote: clientConn.RemoteAddr(),
	}
	m.DialedPeers[p] = mockConn
	fmt.Printf("MockAnonymityProvider: Dialed peer %s\n", p)
	// Return the client side of the pipe
	// A real test would need access to the serverConn side. How? Maybe return both?
	// Or provide a way to retrieve the server side via the mock. Let's keep it simple for now.
	_ = serverConn // Keep server side (maybe close it immediately?)
	return mockConn, nil
}

func (m *MockAnonymityProvider) ListenAnonymously(ctx context.Context) (Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FailListen {
		return nil, errors.New("mock listen failed")
	}
	if m.Listener != nil {
		return nil, errors.New("mock already listening")
	}

	addrToUse := m.expectedListenAddr
	if addrToUse == nil {
		// Default mock address if not set by test
		var err error
		addrToUse, err = multiaddr.NewMultiaddr("/memory/0") // Use in-memory transport addr
		if err != nil {
			return nil, fmt.Errorf("failed to create default mock multiaddr: %w", err)
		}
	}

	m.Listener = NewMockListener(addrToUse)
	fmt.Println("MockAnonymityProvider: Listening on (mock)", addrToUse)
	return m.Listener, nil
}

func (m *MockAnonymityProvider) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Println("MockAnonymityProvider: Closed")
	if m.Listener != nil {
		m.Listener.Close()
	}
	// Close any outstanding connections?
	for pid, conn := range m.DialedPeers {
		conn.Close() // Close the client side
		delete(m.DialedPeers, pid)
	}

	m.Listener = nil
	m.DialedPeers = make(map[peer.ID]Connection) // Reset dialed peers
	return nil
}

// Compile-time check
var _ AnonymityProvider = (*MockAnonymityProvider)(nil)
