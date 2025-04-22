package anonymity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test" // For generating random PeerIDs
	"github.com/multiformats/go-multiaddr"
)

// --- MockConnection --- (Keep as before)
type MockConnection struct {
	io.Reader
	io.Writer
	io.Closer
	Local  net.Addr
	Remote net.Addr
}

// --- MockListener --- (Keep as before)
type MockListener struct {
	addr    multiaddr.Multiaddr
	acceptQ chan Connection
	closeCh chan struct{}
	mu      sync.Mutex
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
	select {
	case m.acceptQ <- conn:
		return true
	default:
		return false
	}
}

// --- Mock PubSub Types ---

// MockMessage implements the Message interface for testing.
type MockMessage struct {
	sender peer.ID
	data   []byte
	topic  string
}

func (m *MockMessage) GetFrom() peer.ID { return m.sender }
func (m *MockMessage) GetData() []byte  { return m.data }
func (m *MockMessage) GetTopic() string { return m.topic }

// Ensure MockMessage satisfies the interface
var _ Message = (*MockMessage)(nil)

// MockSubscription implements the Subscription interface for testing.
type MockSubscription struct {
	topic   string
	msgChan chan Message  // Channel where the provider pushes messages
	cancel  func()        // Function to call when Cancel() is invoked
	closeCh chan struct{} // Internal channel to signal closure
	mu      sync.Mutex
	closed  bool
}

func (s *MockSubscription) Next(ctx context.Context) (Message, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg, ok := <-s.msgChan:
		if !ok {
			return nil, errors.New("mock subscription canceled/closed")
		}
		return msg, nil
	case <-s.closeCh:
		return nil, errors.New("mock subscription canceled/closed")
	}
}

func (s *MockSubscription) Cancel() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.closeCh) // Signal closure
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel() // Notify the provider to remove this subscription
	}
}

func (s *MockSubscription) Topic() string {
	return s.topic
}

// Ensure MockSubscription satisfies the interface
var _ Subscription = (*MockSubscription)(nil)

// --- MockAnonymityProvider --- (Updated)

// MockAnonymityProvider implements the AnonymityProvider interface for testing.
type MockAnonymityProvider struct {
	FailDial           bool
	FailListen         bool
	FailPublish        bool // New failure flag
	FailSubscribe      bool // New failure flag
	Listener           *MockListener
	DialedPeers        map[peer.ID]Connection
	expectedListenAddr multiaddr.Multiaddr

	// PubSub related state
	subscriptions map[string][]*MockSubscription // topic -> list of active subscriptions
	pubSubMu      sync.RWMutex                   // Mutex for subscriptions map
	localPeerID   peer.ID                        // A dummy PeerID for this mock provider instance

	mu sync.Mutex // Protect access to Listener/DialedPeers/flags etc.
}

// NewMockAnonymityProvider creates a new mock provider.
func NewMockAnonymityProvider(listenAddr ...multiaddr.Multiaddr) *MockAnonymityProvider {
	// Generate a random peer ID for this mock provider instance
	// Use test.RandPeerIDFatal for convenience in testing setup
	// In a real scenario, this might come from an identity module
	localPeer, _ := test.RandPeerID() // Don't need t *testing.T here

	m := &MockAnonymityProvider{
		DialedPeers:   make(map[peer.ID]Connection),
		subscriptions: make(map[string][]*MockSubscription),
		localPeerID:   localPeer,
	}
	if len(listenAddr) > 0 && listenAddr[0] != nil {
		m.expectedListenAddr = listenAddr[0]
	}
	return m
}

// --- Connection/Listener Methods (Keep as before) ---
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
	clientConn, serverConn := net.Pipe()
	mockConn := &MockConnection{Reader: clientConn, Writer: clientConn, Closer: clientConn, Local: clientConn.LocalAddr(), Remote: clientConn.RemoteAddr()}
	m.DialedPeers[p] = mockConn
	fmt.Printf("MockAnonymityProvider: Dialed peer %s\n", p)
	_ = serverConn // Keep server side (discard for simple mock)
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
		var err error
		addrToUse, err = multiaddr.NewMultiaddr("/memory/0")
		if err != nil {
			return nil, fmt.Errorf("failed to create default mock multiaddr: %w", err)
		}
	}
	m.Listener = NewMockListener(addrToUse)
	fmt.Println("MockAnonymityProvider: Listening on (mock)", addrToUse)
	return m.Listener, nil
}

// --- NEW PubSub Methods ---

func (m *MockAnonymityProvider) PublishAnonymously(ctx context.Context, topic string, data []byte) error {
	m.mu.Lock() // Lock general mutex first for flags
	failPub := m.FailPublish
	m.mu.Unlock()
	if failPub {
		return errors.New("mock publish failed")
	}

	m.pubSubMu.RLock() // Read lock for accessing subscriptions
	defer m.pubSubMu.RUnlock()

	fmt.Printf("MockAnonymityProvider: Publishing %d bytes to topic '%s'\n", len(data), topic)

	subs, ok := m.subscriptions[topic]
	if !ok || len(subs) == 0 {
		fmt.Printf("MockAnonymityProvider: No subscribers for topic '%s'\n", topic)
		return nil // No subscribers, publish is successful but goes nowhere
	}

	msg := &MockMessage{
		sender: m.localPeerID, // Use the provider's dummy ID
		data:   data,
		topic:  topic,
	}

	// Fan out message to all subscribers on this topic
	for _, sub := range subs {
		// Non-blocking send to avoid deadlocks if a subscriber isn't reading
		select {
		case sub.msgChan <- msg:
			// Message sent
		default:
			// Subscriber channel full or closed, message dropped for this sub
			fmt.Printf("MockAnonymityProvider: Dropped message for subscriber on topic '%s' (channel full/closed)\n", topic)
		}
	}

	return nil
}

func (m *MockAnonymityProvider) SubscribeAnonymously(ctx context.Context, topic string) (Subscription, error) {
	m.mu.Lock() // Lock general mutex first for flags
	failSub := m.FailSubscribe
	m.mu.Unlock()
	if failSub {
		return nil, errors.New("mock subscribe failed")
	}

	m.pubSubMu.Lock() // Write lock for modifying subscriptions
	defer m.pubSubMu.Unlock()

	sub := &MockSubscription{
		topic:   topic,
		msgChan: make(chan Message, 16), // Buffered channel
		closeCh: make(chan struct{}),
	}

	// Define the cancel function to remove the subscription from the map
	sub.cancel = func() {
		m.pubSubMu.Lock()
		defer m.pubSubMu.Unlock()

		subs, ok := m.subscriptions[topic]
		if !ok {
			return // Already removed or topic never existed
		}

		// Find and remove the subscription from the slice
		newSubs := make([]*MockSubscription, 0, len(subs)-1)
		for _, s := range subs {
			if s != sub { // Compare pointers
				newSubs = append(newSubs, s)
			}
		}

		if len(newSubs) == 0 {
			delete(m.subscriptions, topic) // Remove topic if no subs left
			fmt.Printf("MockAnonymityProvider: Removed last subscriber for topic '%s'\n", topic)
		} else {
			m.subscriptions[topic] = newSubs
			fmt.Printf("MockAnonymityProvider: Removed subscriber for topic '%s', %d remaining\n", topic, len(newSubs))
		}
		// Also close the message channel from the provider side to signal Next()
		close(sub.msgChan)
	}

	// Add the new subscription to the map
	m.subscriptions[topic] = append(m.subscriptions[topic], sub)
	fmt.Printf("MockAnonymityProvider: Added subscriber for topic '%s', %d total now\n", topic, len(m.subscriptions[topic]))

	return sub, nil
}

// --- Close Method (Updated) ---
func (m *MockAnonymityProvider) Close() error {
	m.mu.Lock() // Lock general mutex first
	defer m.mu.Unlock()

	fmt.Println("MockAnonymityProvider: Close() called")
	if m.Listener != nil {
		m.Listener.Close()
	}
	// Close any outstanding connections?
	for pid, conn := range m.DialedPeers {
		conn.Close()
		delete(m.DialedPeers, pid)
	}
	m.Listener = nil
	m.DialedPeers = make(map[peer.ID]Connection)

	// Cancel all active subscriptions
	m.pubSubMu.Lock() // Lock pubsub mutex
	defer m.pubSubMu.Unlock()
	fmt.Println("MockAnonymityProvider: Cancelling all subscriptions")
	for topic, subs := range m.subscriptions {
		for _, sub := range subs {
			// Call internal cancel without triggering the removal callback again
			sub.mu.Lock()
			if !sub.closed {
				sub.closed = true
				close(sub.closeCh)
				close(sub.msgChan) // Also close msgChan directly
			}
			sub.mu.Unlock()
		}
		delete(m.subscriptions, topic) // Clear topic entry
	}
	m.subscriptions = make(map[string][]*MockSubscription) // Reset map

	return nil
}

// Compile-time check
var _ AnonymityProvider = (*MockAnonymityProvider)(nil)
