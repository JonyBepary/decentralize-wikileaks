package anonymity

import (
	"context"
	"testing"

	// Use a dummy peer ID for testing
	"github.com/libp2p/go-libp2p/core/test"
)

// TestMockAnonymityProvider_Interface confirms mock implements the interface
// and basic methods can be called without errors (in non-failing mode).
func TestMockAnonymityProvider_Interface(t *testing.T) {
	var provider AnonymityProvider = NewMockAnonymityProvider() // Check interface satisfaction

	if provider == nil {
		t.Fatal("NewMockAnonymityProvider returned nil")
	}

	// Test Dial (non-failing)
	dummyPeerID := test.RandPeerIDFatal(t)
	conn, err := provider.DialPeerAnonymously(context.Background(), dummyPeerID)
	if err != nil {
		t.Errorf("DialPeerAnonymously failed unexpectedly: %v", err)
	}
	if conn == nil {
		t.Error("DialPeerAnonymously returned nil connection unexpectedly")
	}
	// We can add more sophisticated checks with net.Pipe later if needed
	_ = conn.Close() // Close the dummy connection

	// Test Listen (non-failing)
	listener, err := provider.ListenAnonymously(context.Background())
	if err != nil {
		t.Errorf("ListenAnonymously failed unexpectedly: %v", err)
	}
	if listener == nil {
		t.Error("ListenAnonymously returned nil listener unexpectedly")
	}
	if listener.Addr() == nil {
		t.Error("Listener Addr() returned nil")
	}
	_ = listener.Close() // Close the listener

	// Test Close
	err = provider.Close()
	if err != nil {
		t.Errorf("Close failed unexpectedly: %v", err)
	}
}

// TestMockAnonymityProvider_FailModes checks if failure flags work.
func TestMockAnonymityProvider_FailModes(t *testing.T) {
	mockProvider := NewMockAnonymityProvider()

	// Test Dial failure
	mockProvider.FailDial = true
	dummyPeerID := test.RandPeerIDFatal(t)
	_, err := mockProvider.DialPeerAnonymously(context.Background(), dummyPeerID)
	if err == nil {
		t.Error("DialPeerAnonymously should have failed but didn't")
	}

	// Test Listen failure
	mockProvider.FailListen = true
	_, err = mockProvider.ListenAnonymously(context.Background())
	if err == nil {
		t.Error("ListenAnonymously should have failed but didn't")
	}
}

// TODO: Add tests for MockListener Accept/Close/InjectConnection behaviour
