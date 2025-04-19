package onion

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHopInfoSerialization(t *testing.T) {
	// Create a test peer ID
	testID, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	require.NoError(t, err, "Should create test peer ID")

	// Create a hop info
	original := &HopInfo{
		NextPeer: testID,
	}

	// Encode
	encoded, err := EncodeHopInfo(original)
	require.NoError(t, err, "HopInfo encoding should not fail")
	require.NotNil(t, encoded, "Encoded bytes should not be nil")
	require.True(t, len(encoded) > 0, "Encoded bytes should not be empty")

	// Decode
	decoded, err := DecodeHopInfo(encoded)
	require.NoError(t, err, "HopInfo decoding should not fail")
	require.NotNil(t, decoded, "Decoded HopInfo should not be nil")

	// Compare
	assert.Equal(t, original.NextPeer.String(), decoded.NextPeer.String(), "Peer IDs should match after encode/decode")
}

func TestOnionPacketSerialization(t *testing.T) {
	// Create a test peer ID
	testID, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	require.NoError(t, err, "Should create test peer ID")

	// Create sample payload
	payload := []byte("Encrypted payload for testing")

	// Create an onion packet
	original := &OnionPacket{
		HopInfo: HopInfo{
			NextPeer: testID,
		},
		EncryptedPayload: payload,
	}

	// Encode
	encoded, err := EncodeOnionPacket(original)
	require.NoError(t, err, "OnionPacket encoding should not fail")
	require.NotNil(t, encoded, "Encoded bytes should not be nil")
	require.True(t, len(encoded) > 0, "Encoded bytes should not be empty")

	// Decode
	decoded, err := DecodeOnionPacket(encoded)
	require.NoError(t, err, "OnionPacket decoding should not fail")
	require.NotNil(t, decoded, "Decoded OnionPacket should not be nil")

	// Compare
	assert.Equal(t, original.HopInfo.NextPeer.String(), decoded.HopInfo.NextPeer.String(), "Peer IDs should match after encode/decode")
	assert.True(t, bytes.Equal(original.EncryptedPayload, decoded.EncryptedPayload), "Encrypted payloads should match")
}

func TestInnerPayloadSerialization(t *testing.T) {
	// Create a test peer ID
	testID, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	require.NoError(t, err, "Should create test peer ID")

	// Test cases with different message types and data
	testCases := []struct {
		name        string
		messageType uint
		data        []byte
	}{
		{
			name:        "Publish Document",
			messageType: MessageTypePublishDocument,
			data:        []byte("Classified document contents"),
		},
		{
			name:        "Request Block",
			messageType: MessageTypeRequestBlock,
			data:        []byte("Request for block ID: 1234567890"),
		},
		{
			name:        "Response",
			messageType: MessageTypeResponse,
			data:        []byte("Response data for previous request"),
		},
		{
			name:        "Empty data",
			messageType: MessageTypeAnnouncement,
			data:        []byte{},
		},
		{
			name:        "Binary data",
			messageType: MessageTypeResponse,
			data:        []byte{0x00, 0x01, 0x02, 0x03, 0xF0, 0xFF},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create an inner payload
			original := &InnerPayload{
				FinalRecipient: testID,
				MessageType:    tc.messageType,
				Data:           tc.data,
			}

			// Encode
			encoded, err := EncodeInnerPayload(original)
			require.NoError(t, err, "InnerPayload encoding should not fail")
			require.NotNil(t, encoded, "Encoded bytes should not be nil")
			require.True(t, len(encoded) > 0, "Encoded bytes should not be empty")

			// Decode
			decoded, err := DecodeInnerPayload(encoded)
			require.NoError(t, err, "InnerPayload decoding should not fail")
			require.NotNil(t, decoded, "Decoded InnerPayload should not be nil")

			// Compare
			assert.Equal(t, original.FinalRecipient.String(), decoded.FinalRecipient.String(), "Recipient IDs should match")
			assert.Equal(t, original.MessageType, decoded.MessageType, "Message types should match")
			assert.True(t, bytes.Equal(original.Data, decoded.Data), "Data should match")
		})
	}
}

func TestSerializationCornerCases(t *testing.T) {
	t.Run("Invalid encoded data", func(t *testing.T) {
		// Test decoding corrupted or invalid data
		invalid := []byte("this is not valid gob encoded data")

		_, err := DecodeHopInfo(invalid)
		assert.Error(t, err, "Should error when decoding invalid HopInfo")

		_, err = DecodeOnionPacket(invalid)
		assert.Error(t, err, "Should error when decoding invalid OnionPacket")

		_, err = DecodeInnerPayload(invalid)
		assert.Error(t, err, "Should error when decoding invalid InnerPayload")
	})

	t.Run("Empty data", func(t *testing.T) {
		// Test decoding empty data
		empty := []byte{}

		_, err := DecodeHopInfo(empty)
		assert.Error(t, err, "Should error when decoding empty HopInfo")

		_, err = DecodeOnionPacket(empty)
		assert.Error(t, err, "Should error when decoding empty OnionPacket")

		_, err = DecodeInnerPayload(empty)
		assert.Error(t, err, "Should error when decoding empty InnerPayload")
	})
}

func TestProtocolConstantConsistency(t *testing.T) {
	// Ensure protocol constants are defined and in expected format
	assert.NotEmpty(t, CircuitSetupProtocol, "CircuitSetupProtocol should be defined")
	assert.NotEmpty(t, CircuitTeardownProtocol, "CircuitTeardownProtocol should be defined")
	assert.NotEmpty(t, RelayProtocol, "RelayProtocol should be defined")

	// Verify protocol follows expected format /wikileaks/...
	assert.Contains(t, CircuitSetupProtocol, "/wikileaks/", "Protocol should contain correct namespace")
	assert.Contains(t, RelayProtocol, "/wikileaks/", "Protocol should contain correct namespace")
	assert.Contains(t, CircuitTeardownProtocol, "/wikileaks/", "Protocol should contain correct namespace")

	// Verify all protocols have version numbers
	assert.Contains(t, CircuitSetupProtocol, "/1.0.0", "Protocol should contain version")
	assert.Contains(t, RelayProtocol, "/1.0.0", "Protocol should contain version")
	assert.Contains(t, CircuitTeardownProtocol, "/1.0.0", "Protocol should contain version")
}
