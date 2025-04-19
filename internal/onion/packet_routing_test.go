package onion

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOnionPacketCreationAndRouting tests the full process of creating and routing
// an onion-encrypted packet through multiple hops
func TestOnionPacketCreationAndRouting(t *testing.T) {
	// Generate keys for three relay nodes
	numRelays := 3
	relayKeys := make([][]byte, numRelays)

	for i := 0; i < numRelays; i++ {
		key := make([]byte, 32)
		for j := 0; j < 32; j++ {
			key[j] = byte((i + 1) * (j + 1)) // Deterministic pattern for testing
		}
		relayKeys[i] = key
	}

	// Create inner payload (the message that will be delivered to the final recipient)
	finalRecipient, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	require.NoError(t, err, "Should be able to create peer ID")

	innerPayload := &InnerPayload{
		FinalRecipient: finalRecipient,
		MessageType:    MessageTypePublishDocument,
		Data:           []byte("This is a secret document for WikiLeaks"),
	}

	// Encode the inner payload
	innerPayloadBytes, err := EncodeInnerPayload(innerPayload)
	require.NoError(t, err, "Should encode inner payload")

	// Create a dummy path (needed for the function signature)
	path := make([]peer.ID, numRelays+1)
	for i := 0; i < numRelays; i++ {
		p, _ := peer.Decode(fmt.Sprintf("12D3KooWExamplePeer%d", i+1))
		path[i] = p
	}
	p, _ := peer.Decode("12D3KooWExamplePeerDest")
	path[numRelays] = p

	// Create the onion layers (encrypting from the inside out) using the new signature
	// The path for CreateOnionLayers should only contain the relays.
	relayPath := path[:numRelays]
	onionPacket, err := CreateOnionLayers(relayPath, relayKeys, finalRecipient, innerPayloadBytes)
	require.NoError(t, err, "Should create onion layers")

	// Now simulate the packet traversing the network
	currentPacket := onionPacket

	// Each relay peels one layer of encryption
	for i := 0; i < numRelays; i++ {
		t.Logf("Relay %d processing packet", i+1)

		// Decrypt this layer
		decrypted, err := DecryptPayload(relayKeys[i], currentPacket)
		require.NoError(t, err, "Relay %d should decrypt its layer", i+1)

		// Check if intermediate or exit node
		if i < numRelays-1 { // Intermediate Relay
			// Decode the LayeredPayload
			layeredPayload, err := DecodeLayeredPayload(decrypted)
			require.NoError(t, err, "Should decode LayeredPayload at relay %d", i+1)
			// Pass the *inner* encrypted payload to the next relay
			currentPacket = layeredPayload.Payload
		} else { // Exit Node
			// The decrypted data should be the InnerPayload
			currentPacket = decrypted
		}
	}

	// Now the final packet (after exit node decryption) should be our original inner payload
	recoveredInnerPayload, err := DecodeInnerPayload(currentPacket)
	require.NoError(t, err, "Should decode inner payload after all layers removed")

	// Verify the recovered payload matches the original
	assert.Equal(t, innerPayload.FinalRecipient, recoveredInnerPayload.FinalRecipient, "Final recipient should match")
	assert.Equal(t, innerPayload.MessageType, recoveredInnerPayload.MessageType, "Message type should match")
	assert.Equal(t, innerPayload.Data, recoveredInnerPayload.Data, "Payload data should match")
}

// TestHopInfoEncoding tests the encoding and decoding of hop information
func TestHopInfoEncoding(t *testing.T) {
	// Create a peer ID for testing
	testID, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	require.NoError(t, err, "Should be able to create peer ID")

	// Create a hop info object
	original := &HopInfo{
		NextPeer: testID,
	}

	// Encode the hop info
	encoded, err := EncodeHopInfo(original)
	require.NoError(t, err, "Should encode hop info")
	require.NotNil(t, encoded, "Encoded bytes should not be nil")

	// Decode the hop info
	decoded, err := DecodeHopInfo(encoded)
	require.NoError(t, err, "Should decode hop info")

	// Verify the decoded hop info matches the original
	assert.Equal(t, original.NextPeer.String(), decoded.NextPeer.String(), "Peer ID should match after encoding/decoding")
}

// TestOnionPacketEncoding tests the encoding and decoding of the full onion packet
func TestOnionPacketEncoding(t *testing.T) {
	// Create a peer ID for testing
	testID, err := peer.Decode("12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf")
	require.NoError(t, err, "Should be able to create peer ID")

	// Create a HopInfo
	hopInfo := HopInfo{
		NextPeer: testID,
	}

	// Create an encrypted payload
	payload := []byte("This is an encrypted payload for testing")

	// Create the onion packet
	original := &OnionPacket{
		HopInfo:          hopInfo,
		EncryptedPayload: payload,
	}

	// Encode the packet
	encoded, err := EncodeOnionPacket(original)
	require.NoError(t, err, "Should encode onion packet")
	require.NotNil(t, encoded, "Encoded bytes should not be nil")

	// Decode the packet
	decoded, err := DecodeOnionPacket(encoded)
	require.NoError(t, err, "Should decode onion packet")

	// Verify the decoded packet matches the original
	assert.Equal(t, original.HopInfo.NextPeer.String(), decoded.HopInfo.NextPeer.String(), "NextPeer should match")
	assert.True(t, bytes.Equal(original.EncryptedPayload, decoded.EncryptedPayload), "EncryptedPayload should match")
}

// TestOnionNetworkTraversal simulates a packet traversing a multi-hop network
func TestOnionNetworkTraversal(t *testing.T) {
	// Create a sequence of peer IDs representing a path through the network
	peerIDStrings := []string{
		"12D3KooWGzxzKZYveHXtpG6AsrUJBcWxHBFS2HsEoGTxrMLvKXtf", // Origin
		"12D3KooWJbJFaZ3k5sNd8DjQgg3aERoKtBAnirEvPV8yp76kEXHB", // Relay 1
		"12D3KooWCKCDsLkUJTMFPhPEXuKxBAGXXXABcRdqE8Vm63UCko1o", // Relay 2
		"12D3KooWKRyzVWW6ChFjQjK4miCty85Niy48tpPV95XdKu1BcvMA", // Relay 3
		"12D3KooWRYh3aCjoFiShnh5FJRY4UzHKrNwwsPZYQbLMy3HVBfPg", // Destination
	}

	// Convert strings to peer.ID objects
	peerIDs := make([]peer.ID, len(peerIDStrings))
	for i, idStr := range peerIDStrings {
		peerID, err := peer.Decode(idStr)
		require.NoError(t, err, "Should decode peer ID string %s", idStr)
		peerIDs[i] = peerID
	}

	// Generate symmetric keys for each hop
	relayKeys := make([][]byte, 3) // 3 relays
	for i := 0; i < 3; i++ {
		key := make([]byte, 32)
		for j := 0; j < 32; j++ {
			key[j] = byte((i + 1) * (j + 1)) // Deterministic pattern for testing
		}
		relayKeys[i] = key
	}

	// Create the inner payload (message for final recipient)
	finalMessage := "Top secret document about government surveillance programs"
	innerPayload := &InnerPayload{
		FinalRecipient: peerIDs[4], // Destination
		MessageType:    MessageTypePublishDocument,
		Data:           []byte(finalMessage),
	}

	// Encode the inner payload
	innerPayloadBytes, err := EncodeInnerPayload(innerPayload)
	require.NoError(t, err, "Should encode inner payload")

	// Create the onion packet with multiple layers of encryption using the new signature
	// Path for CreateOnionLayers should only include the relays: R1, R2, R3
	relayPath := peerIDs[1:4]    // Slice includes index 1, 2, 3 (Relays)
	finalRecipient := peerIDs[4] // Destination
	onionPacket, err := CreateOnionLayers(relayPath, relayKeys, finalRecipient, innerPayloadBytes)
	require.NoError(t, err, "Should create onion layers")

	// Simulate the packet traversing the network (3 relays)
	currentPacket := onionPacket

	// For each relay in the circuit:
	for i := 0; i < 3; i++ {
		// The relay decrypts its layer
		decrypted, err := DecryptPayload(relayKeys[i], currentPacket)
		require.NoError(t, err, "Relay %d should decrypt its layer", i+1)

		// Relay 0 and 1 will find a LayeredPayload containing the next hop and the inner encrypted data
		// Relay 2 (exit node) will find the InnerPayload
		if i < len(relayKeys)-1 { // Intermediate Relays
			// Intermediate relays should find a LayeredPayload
			layeredPayload, err := DecodeLayeredPayload(decrypted)
			require.NoError(t, err, "Should decode LayeredPayload at relay %d", i+1)

			// Verify this relay knows where to forward to (the next relay in the path)
			expectedNextHop := peerIDs[i+2] // Path was peerIDs[1:4], so next hop is i+1+1 = i+2
			assert.Equal(t, expectedNextHop.String(), layeredPayload.NextHop.String(),
				"Relay %d should forward to correct next hop %s", i+1, expectedNextHop)

			// The payload for the next hop is the inner encrypted data
			currentPacket = layeredPayload.Payload
		} else { // Exit Node (i == len(relayKeys)-1)
			// Exit relay should find the InnerPayload
			recovered, err := DecodeInnerPayload(decrypted)
			require.NoError(t, err, "Exit relay should decode InnerPayload")

			// Verify payload integrity
			assert.Equal(t, peerIDs[4], recovered.FinalRecipient, "Final recipient should match")
			assert.Equal(t, uint(MessageTypePublishDocument), recovered.MessageType, "Message type should match") // Cast expected value
			assert.Equal(t, finalMessage, string(recovered.Data), "Message content should match")
		}
	}
}
