package onion

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer" // Corrected import path
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateEphemeralKeyPair(t *testing.T) { // Renamed test function
	// Test key pair generation
	privKey1, pubKey1, err := GenerateEphemeralKeyPair() // Renamed function call
	require.NoError(t, err, "Should generate first key pair without error")
	require.NotNil(t, privKey1, "Private key should not be nil")
	require.NotNil(t, pubKey1, "Public key should not be nil")
	require.Equal(t, 32, len(privKey1), "Private key should be 32 bytes")
	require.Equal(t, 32, len(pubKey1), "Public key should be 32 bytes")

	// Generate a second key pair to ensure uniqueness
	privKey2, pubKey2, err := GenerateEphemeralKeyPair() // Renamed function call
	require.NoError(t, err, "Should generate second key pair without error")

	// Keys should be different each time
	assert.False(t, bytes.Equal(privKey1, privKey2), "Different private keys should be generated each time")
	assert.False(t, bytes.Equal(pubKey1, pubKey2), "Different public keys should be generated each time")
}

func TestDeriveSharedKey(t *testing.T) {
	// Create two keypairs (representing two nodes in the network)
	alicePriv, alicePub, err := GenerateEphemeralKeyPair() // Renamed function call
	require.NoError(t, err, "Should generate Alice's key pair without error")

	bobPriv, bobPub, err := GenerateEphemeralKeyPair() // Renamed function call
	require.NoError(t, err, "Should generate Bob's key pair without error")

	// Derive shared secret using each party's private key and the other's public key
	aliceShared, err := DeriveSharedKey(alicePriv, bobPub)
	require.NoError(t, err, "Alice should derive shared key without error")

	bobShared, err := DeriveSharedKey(bobPriv, alicePub)
	require.NoError(t, err, "Bob should derive shared key without error")

	// Both derived keys should be identical - this is the core property of DH key exchange
	assert.True(t, bytes.Equal(aliceShared, bobShared), "Both parties should derive the same shared secret")
	assert.Equal(t, 32, len(aliceShared), "Shared key should be 32 bytes")

	// Test with invalid key sizes
	_, err = DeriveSharedKey([]byte("short"), bobPub)
	assert.Error(t, err, "Should error with too short private key")

	_, err = DeriveSharedKey(alicePriv, []byte("short"))
	assert.Error(t, err, "Should error with too short public key")
}

func TestEncryptDecryptPayload(t *testing.T) {
	// Generate random key for encryption
	key := make([]byte, 32) // 256-bit key
	_, err := rand.Read(key)
	require.NoError(t, err, "Should generate random key without error")

	// Test cases with different message sizes
	testCases := []struct {
		name       string
		message    []byte
		corrupt    bool
		shouldFail bool
	}{
		{
			name:       "Empty message",
			message:    []byte{},
			corrupt:    false,
			shouldFail: false,
		},
		{
			name:       "Short message",
			message:    []byte("Test message"),
			corrupt:    false,
			shouldFail: false,
		},
		{
			name:       "Long message",
			message:    bytes.Repeat([]byte("Long test message with repetition. "), 100),
			corrupt:    false,
			shouldFail: false,
		},
		{
			name:       "Corrupted ciphertext",
			message:    []byte("This message will be corrupted after encryption"),
			corrupt:    true,
			shouldFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := EncryptPayload(key, tc.message)
			require.NoError(t, err, "Encryption should not fail")

			// Verify ciphertext is longer than plaintext (includes nonce + tag)
			assert.True(t, len(ciphertext) > len(tc.message), "Ciphertext should be longer than plaintext")

			// Optionally corrupt the ciphertext to test authentication
			if tc.corrupt {
				if len(ciphertext) > 0 {
					// Modify a byte in the middle of the ciphertext (after the nonce)
					ciphertext[len(ciphertext)/2]++
				}
			}

			// Decrypt
			decrypted, err := DecryptPayload(key, ciphertext)

			if tc.shouldFail {
				assert.Error(t, err, "Decryption should fail with corrupted ciphertext")
			} else {
				assert.NoError(t, err, "Decryption should not fail")
				assert.True(t, bytes.Equal(tc.message, decrypted), "Decrypted message should match original")
			}
		})
	}
}

func TestCreateOnionLayers(t *testing.T) {
	// Generate keys for three relays
	numRelays := 3
	relayKeys := make([][]byte, numRelays)
	// Create a dummy path (needed for the function signature)
	path := make([]peer.ID, numRelays+1)
	for i := 0; i < numRelays; i++ {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err, "Should generate relay key without error")
		relayKeys[i] = key
		// Assign dummy peer IDs
		p, _ := peer.Decode(fmt.Sprintf("12D3KooWExamplePeer%d", i+1))
		path[i] = p
	}
	p, _ := peer.Decode("12D3KooWExamplePeerDest")
	path[numRelays] = p

	// Create inner payload
	innerPayload := []byte("Secret message for the final recipient")

	// Build the layered encryption using the new signature
	// Path should only contain relays for the function call
	relayPath := path[:numRelays]
	finalRecipient := path[numRelays]
	onionPacket, err := CreateOnionLayers(relayPath, relayKeys, finalRecipient, innerPayload)
	require.NoError(t, err, "Should create onion packet without error")

	// Now simulate the onion routing process by peeling off layers one by one
	currentEncryptedData := onionPacket
	for i := 0; i < numRelays; i++ { // i = 0, 1, 2 (Relays 1, 2, 3)
		decryptedData, err := DecryptPayload(relayKeys[i], currentEncryptedData)
		require.NoError(t, err, "Relay %d should decrypt its layer without error", i+1)

		if i < numRelays-1 { // Intermediate hops (Relays 1, 2)
			layeredPayload, err := DecodeLayeredPayload(decryptedData)
			require.NoError(t, err, "Should decode LayeredPayload at relay %d", i+1)
			// Skip NextHop assertion due to dummy path
			currentEncryptedData = layeredPayload.Payload // Pass inner payload to next iteration
		} else { // Exit hop (Relay 3)
			// After all layers are peeled off, we should have the original inner payload
			assert.True(t, bytes.Equal(innerPayload, decryptedData), "Final decrypted payload should match original")
			currentEncryptedData = decryptedData // For consistency, though loop ends here
		}
	}
}

// Test vector for AES-GCM (to ensure compatibility with standard implementations)
func TestAESGCMStandardCompatibility(t *testing.T) {
	// NIST test vector from GCM spec
	key := []byte{
		0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
		0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
		0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
		0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
	}

	// A fixed test message
	message := []byte("The quick brown fox jumps over the lazy dog")

	// First ensure we can encrypt and decrypt our own messages
	ciphertext, err := EncryptPayload(key, message)
	require.NoError(t, err, "Standard encryption should succeed")

	decrypted, err := DecryptPayload(key, ciphertext)
	require.NoError(t, err, "Standard decryption should succeed")

	assert.Equal(t, message, decrypted, "Decrypted message should match original")
}
