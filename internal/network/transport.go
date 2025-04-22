package network

import (
	"context"
	"fmt"
	"net"

	"github.com/jonybepary/decentralize-wikileaks/internal/anonymity" // Adjust import path
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol" // Needed for scope interfaces
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	// Import OpenTelemetry attribute package for ScopeSpanAttribute
	"go.opentelemetry.io/otel/attribute"
)

// anonymousTransport implements the libp2p transport.Transport interface,
// delegating operations to an underlying AnonymityProvider.
type anonymousTransport struct {
	provider anonymity.AnonymityProvider
}

// Ensure anonymousTransport satisfies the transport.Transport interface at compile time
var _ transport.Transport = (*anonymousTransport)(nil)

// NewAnonymousTransport creates a transport that wraps the given anonymity provider.
func NewAnonymousTransport(provider anonymity.AnonymityProvider) *anonymousTransport {
	return &anonymousTransport{
		provider: provider,
	}
}

// Dial attempts to establish an outbound connection via the anonymity provider.
func (t *anonymousTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	fmt.Printf("AnonymousTransport: Dialing %s (addr hint: %s)\n", p, raddr)
	anonConn, err := t.provider.DialPeerAnonymously(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("anonymity provider failed to dial %s: %w", p, err)
	}

	localMa, _ := ma.NewMultiaddr("/memory/anon-dialer") // Dummy local addr
	remoteMa := raddr

	capableConn := &anonCapableConn{
		Connection: anonConn, // Use embedded field name (anonymity.Connection)
		transport:  t,
		localMa:    localMa,
		remoteMa:   remoteMa,
		remotePeer: p,
	}
	fmt.Printf("AnonymousTransport: Dial to %s successful\n", p)
	return capableConn, nil
}

// Listen creates a listener that accepts incoming connections via the anonymity provider.
func (t *anonymousTransport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	fmt.Printf("AnonymousTransport: Listening (hint addr: %s)\n", laddr)
	anonListener, err := t.provider.ListenAnonymously(context.Background())
	if err != nil {
		return nil, fmt.Errorf("anonymity provider failed to listen: %w", err)
	}

	netAddr, err := manet.ToNetAddr(anonListener.Addr())
	if err != nil {
		fmt.Printf("Warning: could not convert listener multiaddr %s to net.Addr: %v. Using dummy.\n", anonListener.Addr(), err)
		netAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0} // Dummy net.Addr
	}

	transportListener := &anonListenerWrapper{
		Listener:  anonListener,
		transport: t,
		netAddr:   netAddr, // Store the converted net.Addr
	}
	fmt.Printf("AnonymousTransport: Listening on %s (net: %s)\n", transportListener.Multiaddr(), transportListener.Addr())
	return transportListener, nil
}

// Protocols returns the set of protocols handled by this transport.
func (t *anonymousTransport) Protocols() []int {
	return []int{ma.P_MEMORY}
}

// CanDial checks if this transport can dial the given multiaddr.
func (t *anonymousTransport) CanDial(addr ma.Multiaddr) bool {
	_, err := addr.ValueForProtocol(ma.P_P2P)
	return err == nil
}

// Proxy indicates if this transport generally goes through proxies.
func (t *anonymousTransport) Proxy() bool {
	return false
}

// --- Wrapper types ---

// anonListenerWrapper wraps anonymity.Listener to implement transport.Listener
type anonListenerWrapper struct {
	anonymity.Listener
	transport transport.Transport
	netAddr   net.Addr
}

var _ transport.Listener = (*anonListenerWrapper)(nil) // Ensure interface satisfaction

func (l *anonListenerWrapper) Accept() (transport.CapableConn, error) {
	anonConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	localMa := l.Multiaddr()
	remoteMa, _ := ma.NewMultiaddr("/memory/anon-incoming")
	unknownPeer := peer.ID("") // Limitation: cannot easily get peer ID here

	capableConn := &anonCapableConn{
		Connection: anonConn,
		transport:  l.transport,
		localMa:    localMa,
		remoteMa:   remoteMa,
		remotePeer: unknownPeer,
	}
	return capableConn, nil
}

// Addr returns the net.Addr for the listener.
func (l *anonListenerWrapper) Addr() net.Addr {
	return l.netAddr
}

// Multiaddr returns the multiaddr for the listener.
func (l *anonListenerWrapper) Multiaddr() ma.Multiaddr {
	return l.Listener.Addr()
}

// --- anonCapableConn ---

// anonCapableConn wraps anonymity.Connection to implement transport.CapableConn
type anonCapableConn struct {
	anonymity.Connection // Embed the connection
	transport            transport.Transport
	localMa              ma.Multiaddr
	remoteMa             ma.Multiaddr
	remotePeer           peer.ID
}

var _ transport.CapableConn = (*anonCapableConn)(nil) // Ensure interface satisfaction

func (c *anonCapableConn) Conn() manet.Conn {
	if nc, ok := c.Connection.(manet.Conn); ok {
		return nc
	}
	return nil
}
func (c *anonCapableConn) Transport() transport.Transport { return c.transport }

// --- network.ConnSecurity ---
func (c *anonCapableConn) LocalPeer() peer.ID                 { return "" }
func (c *anonCapableConn) LocalPrivateKey() crypto.PrivKey    { return nil }
func (c *anonCapableConn) RemotePeer() peer.ID                { return c.remotePeer }
func (c *anonCapableConn) RemotePublicKey() crypto.PubKey     { return nil }
func (c *anonCapableConn) ConnState() network.ConnectionState { return network.ConnectionState{} }

// --- network.ConnMultiaddrs ---
func (c *anonCapableConn) LocalMultiaddr() ma.Multiaddr  { return c.localMa }
func (c *anonCapableConn) RemoteMultiaddr() ma.Multiaddr { return c.remoteMa }

// --- network.Conn ---
// Read, Write, Close are embedded via anonymity.Connection
func (c *anonCapableConn) ID() string                   { return "" }
func (c *anonCapableConn) Stat() network.Stats          { return network.Stats{} }
func (c *anonCapableConn) GetStreams() []network.Stream { return nil }
func (c *anonCapableConn) IsClosed() bool               { return false } // Needs proper implementation
func (c *anonCapableConn) AcceptStream() (network.MuxedStream, error) {
	return nil, fmt.Errorf("AcceptStream not implemented")
}
func (c *anonCapableConn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	return nil, fmt.Errorf("OpenStream not implemented")
}
func (c *anonCapableConn) CloseWithError(errCode network.ConnErrorCode) error {
	return c.Connection.Close()
}
func (c *anonCapableConn) Scope() network.ConnScope { return &noopScope{} }

// --- Minimal Scope Implementation for Stubs ---

// noopResourceScopeSpan provides a basic, no-op implementation of network.ResourceScopeSpan
type noopResourceScopeSpan struct{}

var _ network.ResourceScopeSpan = (*noopResourceScopeSpan)(nil)

func (s *noopResourceScopeSpan) Done()                            {}
func (s *noopResourceScopeSpan) SetError(error)                   {}
func (s *noopResourceScopeSpan) Name() string                     { return "noopspan" }
func (s *noopResourceScopeSpan) Attributes() []attribute.KeyValue { return nil }
func (s *noopResourceScopeSpan) BeginSpan() (network.ResourceScopeSpan, error) {
	return &noopResourceScopeSpan{}, nil
}
func (s *noopResourceScopeSpan) ReserveMemory(size int, prio uint8) error { return nil } // Always succeed
func (s *noopResourceScopeSpan) ReleaseMemory(size int)                   {}

// ADDED Stat method
func (s *noopResourceScopeSpan) Stat() network.ScopeStat { return network.ScopeStat{} }

// noopResourceScope provides a basic, no-op implementation of network.ResourceScope
type noopResourceScope struct{}

var _ network.ResourceScope = (*noopResourceScope)(nil)

func (s *noopResourceScope) Name() string                             { return "noop" }
func (s *noopResourceScope) Service() string                          { return "" }
func (s *noopResourceScope) Protocol() protocol.ID                    { return "" }
func (s *noopResourceScope) Peer() peer.ID                            { return "" }
func (s *noopResourceScope) ReserveMemory(size int, prio uint8) error { return nil } // Correctly belongs here
func (s *noopResourceScope) ReleaseMemory(size int)                   {}             // Correctly belongs here
func (s *noopResourceScope) Done()                                    {}
func (s *noopResourceScope) Stat() network.ScopeStat                  { return network.ScopeStat{} } // Correct type
func (s *noopResourceScope) BeginSpan() (network.ResourceScopeSpan, error) {
	return &noopResourceScopeSpan{}, nil
} // Correctly belongs here

// noopScope provides a basic, no-op implementation of network.ConnScope
type noopScope struct{}

var _ network.ConnScope = (*noopScope)(nil)

func (s *noopScope) PeerScope() network.ResourceScope      { return &noopResourceScope{} }
func (s *noopScope) TransportScope() network.ResourceScope { return &noopResourceScope{} }
func (s *noopScope) SystemScope() network.ResourceScope    { return &noopResourceScope{} }
func (s *noopScope) ServiceScope(svc string) (network.ResourceScope, error) {
	return &noopResourceScope{}, nil
}
func (s *noopScope) ProtocolScope(proto protocol.ID) (network.ResourceScope, error) {
	return &noopResourceScope{}, nil
}
func (s *noopScope) Done() {}
func (s *noopScope) BeginSpan() (network.ResourceScopeSpan, error) {
	return &noopResourceScopeSpan{}, nil
}

// ADDED ReserveMemory and ReleaseMemory to satisfy potential implicit requirements or future changes
// Although ConnScope doesn't *directly* list these, underlying operations might expect them.
// Returning nil/noop is safe for this mock.
func (s *noopScope) ReserveMemory(size int, prio uint8) error { return nil }
func (s *noopScope) ReleaseMemory(size int)                   {}
func (s *noopScope) Stat() network.ScopeStat                  { return network.ScopeStat{} }
