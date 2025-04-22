package network

import (
	"context"
	"fmt"

	"github.com/jonybepary/decentralize-wikileaks/internal/anonymity" // Adjust import path
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/transport"
	// Removed rcmgr import
)

// CreateLibp2pHost creates a new libp2p Host, configured to use a specific AnonymityProvider.
func CreateLibp2pHost(ctx context.Context, privKey crypto.PrivKey, provider anonymity.AnonymityProvider, listenAddrStr string) (host.Host, error) {
	if provider == nil {
		return nil, fmt.Errorf("anonymity provider cannot be nil")
	}

	// Create the transport instance
	anonTransport := NewAnonymousTransport(provider)

	// Define options explicitly
	opts := []libp2p.Option{
		libp2p.Identity(privKey),

		// Add the transport directly as an option
		// Use a simpler constructor that matches the expected signature
		libp2p.Transport(func() (transport.Transport, error) {
			return anonTransport, nil
		}),

		// Explicitly add common defaults that might help DI
		libp2p.DefaultMuxers,
		libp2p.DefaultSecurity,
		libp2p.DisableRelay(),
		libp2p.EnableHolePunching(),

		// *** REMOVED explicit ResourceManager option ***
		// Let libp2p.New handle resource manager setup internally if needed.
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host with custom transport: %w", err)
	}

	// Check addresses after creation - expect default listeners now
	fmt.Printf("Host created with ID: %s (using %T)\n", h.ID(), provider)
	fmt.Println("Listening on addresses (reported by host after creation):")
	allAddrs := h.Addrs()
	if len(allAddrs) == 0 {
		fmt.Println("Warning: Host reported no addresses after creation.")
	}
	for _, addr := range allAddrs {
		fmt.Printf(" - %s\n", addr)
	}

	// Note: The test TestCreateLibp2pHost might fail now because it expects *no* default addresses.
	// We can adjust the test later if this host creation approach works.

	return h, nil
}
