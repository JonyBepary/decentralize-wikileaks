package p2p

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	// We might need our crypto package later if node ID needs to be tied to AccountID
	// "github.com/sohelahmedjony/decentralize-wikileaks/internal/crypto"
)

// CreateNode initializes a new libp2p host (node).
func CreateNode(ctx context.Context, listenPort int) (host.Host, error) {
	// Creates a new RSA key pair for this host.
	// In a real app, you might want to load/save the key pair.
	// We could also use crypto.GenerateAccount() if the node ID should be the AccountID.
	// priv, _, err := crypto.GenerateAccount() // Example if using our crypto
	// if err != nil {
	// 	return nil, err
	// }
	// privKeyBytes, _ := crypto.GetPrivateKeyBytes(priv)
	// libp2pPrivKey, err := // Convert ed25519 bytes to libp2p crypto.PrivKey

	// Start with the default options
	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort),         // Listen on TCP
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", listenPort), // Listen on QUIC
			fmt.Sprintf("/ip6/::/tcp/%d", listenPort),              // Listen on TCP (IPv6)
			fmt.Sprintf("/ip6/::/udp/%d/quic-v1", listenPort),      // Listen on QUIC (IPv6)
		),
		libp2p.DefaultSecurity, // Use default security transports (TLS, Noise)
		libp2p.DefaultMuxers,   // Use default stream multiplexers (Yamux, Mplex)
		libp2p.NATPortMap(),    // Attempt to open ports using UPnP or NAT-PMP
		// TODO: Add relay options (Circuit Relay v2) later for NAT traversal
		// libp2p.EnableRelay(),
		// libp2p.EnableAutoRelay(),
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	fmt.Printf("[*] Node ID: %s\n", h.ID().String())
	fmt.Println("[*] Listening on addresses:")
	for _, addr := range h.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, h.ID().String())
	}

	return h, nil
}

// Helper function to create a multiaddress from a string
func AddrInfoFromString(addrStr string) (*peer.AddrInfo, error) {
	maddr, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse multiaddr '%s': %w", addrStr, err)
	}
	addrInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get AddrInfo from multiaddr '%s': %w", addrStr, err)
	}
	return addrInfo, nil
}
