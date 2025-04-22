package anonymity

import (
	"context"
	"io" // Needed for connection interface (conceptually)

	"github.com/libp2p/go-libp2p/core/peer" // For PeerID
	"github.com/multiformats/go-multiaddr"  // For Multiaddr
)

// Connection represents an abstract anonymous connection.
// In a real implementation, this would likely wrap a libp2p network.Stream
// or a connection object provided by the underlying anonymity system (like Nym).
// For the mock, it can be simpler. We use io.ReadWriteCloser as a placeholder.
type Connection io.ReadWriteCloser // Placeholder type

// Listener represents an abstract listener for anonymous connections.
type Listener interface {
	Accept() (Connection, error)
	Close() error
	Addr() multiaddr.Multiaddr // The address the listener is bound to
}

// AnonymityProvider defines the interface for interacting with the underlying
// anonymity network (e.g., Nym or a future custom implementation).
type AnonymityProvider interface {
	// DialPeerAnonymously attempts to establish an anonymous connection to a peer.
	DialPeerAnonymously(ctx context.Context, p peer.ID) (Connection, error)

	// ListenAnonymously starts listening for incoming anonymous connections.
	// It might return a multiaddr representing the entry point into the anonymity network.
	ListenAnonymously(ctx context.Context) (Listener, error)

	// Close shuts down the anonymity provider connection/client.
	Close() error

	// TODO: Add methods for anonymous PubSub (Publish/Subscribe)
	// TODO: Add methods for routing IPFS requests if needed
}
