package anonymity

import (
	"context"
	"io"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Connection represents an abstract anonymous connection.
type Connection io.ReadWriteCloser // Placeholder type remains

// Listener represents an abstract listener for anonymous connections.
type Listener interface {
	Accept() (Connection, error)
	Close() error
	Addr() multiaddr.Multiaddr
}

// --- NEW PubSub Types ---

// Message represents a message received from a subscription.
type Message interface {
	// GetFrom returns the identifier of the sender (might be obfuscated).
	GetFrom() peer.ID // Using PeerID, but could be another type depending on provider
	// GetData returns the message payload.
	GetData() []byte
	// GetTopic returns the topic this message was published to.
	GetTopic() string
}

// Subscription represents an active subscription to a topic.
type Subscription interface {
	// Next returns the next message received on the subscription.
	// It blocks until a message is received, the context is canceled,
	// or an error occurs (e.g., the subscription is canceled).
	Next(ctx context.Context) (Message, error)
	// Cancel closes the subscription.
	Cancel()
	// Topic returns the topic string.
	Topic() string
}

// --- END NEW PubSub Types ---

// AnonymityProvider defines the interface for interacting with the underlying
// anonymity network (e.g., Nym or a future custom implementation).
type AnonymityProvider interface {
	// DialPeerAnonymously attempts to establish an anonymous connection to a peer.
	DialPeerAnonymously(ctx context.Context, p peer.ID) (Connection, error)

	// ListenAnonymously starts listening for incoming anonymous connections.
	ListenAnonymously(ctx context.Context) (Listener, error)

	// --- NEW PubSub Methods ---

	// PublishAnonymously sends data to a given topic over the anonymity network.
	PublishAnonymously(ctx context.Context, topic string, data []byte) error

	// SubscribeAnonymously joins a topic and returns a subscription object
	// for receiving messages related to that topic over the anonymity network.
	SubscribeAnonymously(ctx context.Context, topic string) (Subscription, error)

	// --- END NEW PubSub Methods ---

	// Close shuts down the anonymity provider connection/client.
	Close() error

	// TODO: Add methods for routing IPFS requests if needed (may not be needed if handled by transport)
}
