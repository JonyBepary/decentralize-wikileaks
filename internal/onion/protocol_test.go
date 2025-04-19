package onion

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
)

// TestProtocolConstants ensures protocol identifiers are defined and follow
// the expected format and versioning
func TestProtocolConstants(t *testing.T) {
	// Verify protocols are defined
	assert.NotEmpty(t, CircuitSetupProtocol, "CircuitSetupProtocol should be defined")
	assert.NotEmpty(t, CircuitTeardownProtocol, "CircuitTeardownProtocol should be defined")
	assert.NotEmpty(t, RelayProtocol, "RelayProtocol should be defined")

	// Verify protocol format follows the pattern /wikileaks/X/version
	assert.Contains(t, CircuitSetupProtocol, "/wikileaks/", "CircuitSetupProtocol should use the correct namespace")
	assert.Contains(t, CircuitTeardownProtocol, "/wikileaks/", "CircuitTeardownProtocol should use the correct namespace")
	assert.Contains(t, RelayProtocol, "/wikileaks/", "RelayProtocol should use the correct namespace")

	// Verify versioning is present
	assert.Contains(t, CircuitSetupProtocol, "/1.0.0", "CircuitSetupProtocol should have version")
	assert.Contains(t, CircuitTeardownProtocol, "/1.0.0", "CircuitTeardownProtocol should have version")
	assert.Contains(t, RelayProtocol, "/1.0.0", "RelayProtocol should have version")
}

// TestMessageTypeConstants verifies message type constants are properly defined
// Note: Circuit setup/teardown message types (TypeEstablish, etc.) are not tested here,
// but their usage is implicitly tested in circuit building/teardown tests.
func TestMessageTypeConstants(t *testing.T) {
	// Verify message types don't overlap
	assert.NotEqual(t, MessageTypePublishDocument, MessageTypeRequestBlock, "Message types should be distinct")
	assert.NotEqual(t, MessageTypePublishDocument, MessageTypeResponse, "Message types should be distinct")
	assert.NotEqual(t, MessageTypePublishDocument, MessageTypeAnnouncement, "Message types should be distinct")
	assert.NotEqual(t, MessageTypePublishDocument, MessageTypeError, "Message types should be distinct")
	assert.NotEqual(t, MessageTypeRequestBlock, MessageTypeResponse, "Message types should be distinct")
	assert.NotEqual(t, MessageTypeRequestBlock, MessageTypeAnnouncement, "Message types should be distinct")
	assert.NotEqual(t, MessageTypeRequestBlock, MessageTypeError, "Message types should be distinct")
	assert.NotEqual(t, MessageTypeResponse, MessageTypeAnnouncement, "Message types should be distinct")
	assert.NotEqual(t, MessageTypeResponse, MessageTypeError, "Message types should be distinct")
	assert.NotEqual(t, MessageTypeAnnouncement, MessageTypeError, "Message types should be distinct")
}

// TestCircuitSetupMessage tests the setup message structure
func TestCircuitSetupMessage(t *testing.T) {
	// Create a test setup message
	testID, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	assert.NoError(t, err, "Should be able to create test peer ID")

	// Test TypeEstablish message
	setupMsgEstablish := CircuitSetupMessage{
		Type:      TypeEstablish,
		CircuitID: "test-circuit-abc", // Use string
		PublicKey: []byte("test-public-key-data"),
		// NextHopPeerID is not used for TypeEstablish
	}

	// Verify fields for TypeEstablish
	assert.Equal(t, TypeEstablish, setupMsgEstablish.Type, "Type should be TypeEstablish")
	assert.Equal(t, "test-circuit-abc", setupMsgEstablish.CircuitID, "CircuitID should match")
	assert.Equal(t, []byte("test-public-key-data"), setupMsgEstablish.PublicKey, "PublicKey should match")
	assert.Equal(t, peer.ID(""), setupMsgEstablish.NextHopPeerID, "NextHopPeerID should be empty for TypeEstablish") // Verify empty

	// Test TypeExtend message
	setupMsgExtend := CircuitSetupMessage{
		Type:          TypeExtend,
		CircuitID:     "test-circuit-abc", // Use string
		PublicKey:     []byte("encrypted-client-pubkey-for-ri"),
		NextHopPeerID: testID,
	}

	// Verify fields for TypeExtend
	assert.Equal(t, TypeExtend, setupMsgExtend.Type, "Type should be TypeExtend")
	assert.Equal(t, "test-circuit-abc", setupMsgExtend.CircuitID, "CircuitID should match")
	assert.Equal(t, []byte("encrypted-client-pubkey-for-ri"), setupMsgExtend.PublicKey, "PublicKey should match for TypeExtend")
	assert.Equal(t, testID, setupMsgExtend.NextHopPeerID, "NextHopPeerID should match for TypeExtend")
}

// TestCircuitTeardownMessage tests the teardown message structure
func TestCircuitTeardownMessage(t *testing.T) {
	// Create a test teardown message
	teardownMsg := CircuitTeardownMessage{
		CircuitID: "test-circuit-xyz", // Use string
		Reason:    "circuit expired",
	}

	// Verify fields
	assert.Equal(t, "test-circuit-xyz", teardownMsg.CircuitID, "CircuitID should match")
	assert.Equal(t, "circuit expired", teardownMsg.Reason, "Reason should match")
}

// TestCircuitSetupResponse tests the setup response message structure
func TestCircuitSetupResponse(t *testing.T) {
	// Test successful TypeEstablished response
	successRespEstablished := CircuitSetupResponse{
		Type:      TypeEstablished,
		CircuitID: "test-circuit-123", // Use string
		Status:    StatusOK,
		PublicKey: []byte("relay-public-key-data"),
	}

	assert.Equal(t, TypeEstablished, successRespEstablished.Type, "Type should be TypeEstablished")
	assert.Equal(t, "test-circuit-123", successRespEstablished.CircuitID, "CircuitID should match")
	assert.Equal(t, uint8(StatusOK), successRespEstablished.Status, "Status should be StatusOK")
	assert.Equal(t, []byte("relay-public-key-data"), successRespEstablished.PublicKey, "PublicKey should match")

	// Test successful TypeExtended response
	successRespExtended := CircuitSetupResponse{
		Type:      TypeExtended,
		CircuitID: "test-circuit-123", // Use string
		Status:    StatusOK,
		PublicKey: []byte("encrypted-relay-pubkey-data"), // Encrypted in TypeExtended
	}

	assert.Equal(t, TypeExtended, successRespExtended.Type, "Type should be TypeExtended")
	assert.Equal(t, "test-circuit-123", successRespExtended.CircuitID, "CircuitID should match")
	assert.Equal(t, uint8(StatusOK), successRespExtended.Status, "Status should be StatusOK")
	assert.Equal(t, []byte("encrypted-relay-pubkey-data"), successRespExtended.PublicKey, "PublicKey should match for TypeExtended")

	// Test error response (could be for Establish or Extend)
	errorResp := CircuitSetupResponse{
		Type:      TypeEstablished,    // Example: Error during establishment
		CircuitID: "test-circuit-123", // Use string
		Status:    StatusError,
		PublicKey: []byte("failed to derive shared key"), // Error message might be here
	}

	assert.Equal(t, TypeEstablished, errorResp.Type, "Type should match")
	assert.Equal(t, "test-circuit-123", errorResp.CircuitID, "CircuitID should match")
	assert.Equal(t, uint8(StatusError), errorResp.Status, "Status should be StatusError")
	// PublicKey might contain an error message, or be empty
	assert.NotEmpty(t, errorResp.PublicKey, "PublicKey might contain error message")
}
