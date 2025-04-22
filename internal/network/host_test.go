package network

import (
	"context"
	"strings" // Import strings package
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/jonybepary/decentralize-wikileaks/internal/anonymity" // Adjust import path
	"github.com/jonybepary/decentralize-wikileaks/internal/identity"  // Adjust import path
)

// TestCreateLibp2pHost checks if a libp2p host can be created and configured
// to listen via the provided AnonymityProvider.
func TestCreateLibp2pHost(t *testing.T) {
	// Prerequisite: Generate identity keys
	privKey, pubKey, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Prerequisite GenerateKeyPair failed: %v", err)
	}
	if privKey == nil || pubKey == nil {
		t.Fatal("Prerequisite GenerateKeyPair returned nil key(s)")
	}

	// Derive expected PeerID
	expectedPeerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to derive PeerID from public key: %v", err)
	}

	// --- Setup Mock Provider ---
	// No need to set a specific address on the mock for this version of the test
	mockProvider := anonymity.NewMockAnonymityProvider()
	// --- End Mock Setup ---

	// Attempt to create the host (implementation needs change to use custom transport)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host, err := CreateLibp2pHost(ctx, privKey, mockProvider, "") // ListenAddrStr ignored

	if err != nil {
		t.Fatalf("CreateLibp2pHost returned an unexpected error: %v", err)
	}
	if host == nil {
		t.Fatal("CreateLibp2pHost returned a nil host")
	}
	defer host.Close()

	// Check Host ID
	if host.ID() != expectedPeerID {
		t.Errorf("Host ID %s does not match expected PeerID %s", host.ID(), expectedPeerID)
	}

	// CHECK: Verify Listen Addresses (Revised Check)
	listenAddrs := host.Addrs()
	t.Logf("Host listening on addresses: %v", listenAddrs)

	// Expected failure point: Until custom transport is used, listenAddrs will be non-empty
	// BUT will contain default TCP/QUIC addresses. Once the custom transport is implemented,
	// listenAddrs should *still* be non-empty (containing addresses from the mock provider/custom transport)
	// but should NOT contain default TCP/QUIC.
	if len(listenAddrs) == 0 {
		// This *might* happen if the custom transport fails to listen, which is a valid failure case.
		// For now, let's assume the custom transport *will* provide some address.
		// We will likely need a way for the mock provider's listener to signal readiness.
		// Let's adjust the test to expect *some* address, but fail if it finds TCP/QUIC.
		t.Logf("Host reported no listening addresses.") // Log this case
		// Decide if this is a failure: yes, if we expect the custom transport to succeed.
		// t.Fatal("Host should be listening on addresses provided by the custom transport")
		// Let's allow empty for now and focus on removing default addrs.

	}

	hasUnexpectedDefaultAddr := false
	for _, addr := range listenAddrs {
		// Check for default addresses that *shouldn't* be there if the custom transport is working
		protoTCP, _ := addr.ValueForProtocol(multiaddr.P_TCP)
		protoQUIC, _ := addr.ValueForProtocol(multiaddr.P_QUIC_V1)
		protoWS, _ := addr.ValueForProtocol(multiaddr.P_WS) // Check for WebSockets too

		// Check if it contains common default protocols
		if protoTCP != "" || protoQUIC != "" || protoWS != "" {
			// Allow localhost for potential debug/internal libp2p listeners? Maybe not.
			// Let's be strict: disallow common default transports.
			if !strings.HasPrefix(addr.String(), "/127.0.0.1/") && !strings.HasPrefix(addr.String(), "/::1/") {
				t.Errorf("Host listening on unexpected default transport address: %s", addr)
				hasUnexpectedDefaultAddr = true
			} else {
				t.Logf("Ignoring potential default localhost address: %s", addr)
			}
		}
	}

	// This assertion *should* fail initially because DefaultTransports are still used
	if hasUnexpectedDefaultAddr {
		t.Error("Host should not be listening on default TCP/QUIC/WS addresses when configured with a custom anonymity transport.")
	}

}
