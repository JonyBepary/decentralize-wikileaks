package onion

import (
	"context"
	"testing"
	"time"

	// "github.com/libp2p/go-libp2p/core/host" // Removed unused import
	"github.com/libp2p/go-libp2p/core/peer"
	blankhost "github.com/libp2p/go-libp2p/p2p/host/blank"     // Correct alias usage
	swarmt "github.com/libp2p/go-libp2p/p2p/net/swarm/testing" // Added for testing swarm
	"github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/require" // Removed as NewRelay doesn't return error
)

// TestBasicCircuitLifecycle tests the basic lifecycle of a circuit
func TestBasicCircuitLifecycle(t *testing.T) {
	// NOTE: This test still relies on accessing the unexported circuits map directly
	// for insertion and verification, which is not ideal. A full refactor would
	// involve testing via the relay's public API (stream handlers).
	// Using NewRelay primarily to fix the nil logger panic.

	// Create a dummy host with a testing swarm
	ctx := context.Background()
	dummyHost := blankhost.NewBlankHost(swarmt.GenSwarm(t)) // Use testing swarm

	// Create a relay instance using the constructor
	// NewRelay only takes context and host, and doesn't return an error
	relay := NewRelay(ctx, dummyHost) // Pass context
	// require.NoError(t, err, "Failed to create relay") // Removed error check
	// defer relay.Close() // Removed as Relay has no Close method

	// Create a test circuit
	circuitID := "circuit-12345" // Changed type to string
	prevPeer := peer.ID("prev-peer")
	nextPeer := peer.ID("next-peer")
	testKey := []byte("test-circuit-key-12345")

	// Add the circuit directly (bypassing host operations) - Unsafe, needs refactor
	// relay.circuitsMu.Lock() // Cannot access
	relay.circuits[circuitID] = &Circuit{
		ID:         circuitID, // Use exported field name 'ID'
		PrevPeer:   prevPeer,
		NextPeer:   nextPeer,
		SharedKey:  testKey, // Use exported field name 'SharedKey'
		LastActive: time.Now(),
		// IsExitNode, Stream, streamMu not set here
	}
	// relay.circuitsMu.Unlock() // Cannot access
	// Cannot set circuitStatus or lastActivity in separate maps anymore

	// Verify the circuit exists - Direct map access (unsafe)
	// relay.circuitsMu.RLock() // Cannot access
	circuit, exists := relay.circuits[circuitID]
	// relay.circuitsMu.RUnlock() // Cannot access

	assert.True(t, exists, "Circuit should exist")
	assert.NotNil(t, circuit, "Circuit should not be nil")
	if circuit != nil { // Add nil check
		assert.Equal(t, prevPeer, circuit.PrevPeer, "Previous peer should match")
		assert.Equal(t, nextPeer, circuit.NextPeer, "Next peer should match")
		// Cannot check status or separate last activity map
		assert.WithinDuration(t, time.Now(), circuit.LastActive, 1*time.Second, "Last activity should be recent")
	}

	// Test circuit teardown
	relay.teardownCircuit(circuitID) // Call exported method with string ID

	// Verify circuit is gone - Direct map access (unsafe)
	// relay.circuitsMu.RLock() // Cannot access
	_, exists = relay.circuits[circuitID]
	assert.False(t, exists, "Circuit should be removed after teardown")
}
