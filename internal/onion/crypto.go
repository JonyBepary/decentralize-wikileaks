// filepath: /home/jony/Project/decentralize-wikileaks/internal/onion/crypto.go
package onion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/libp2p/go-libp2p/core/peer"
)

// GenerateEphemeralKeyPair creates a new X25519 key pair for circuit setup
func GenerateEphemeralKeyPair() (privateKey, publicKey []byte, err error) {
	var privKey x25519.Key
	var pubKey x25519.Key

	// Generate private key
	_, err = io.ReadFull(rand.Reader, privKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Derive public key
	x25519.KeyGen(&pubKey, &privKey)

	return privKey[:], pubKey[:], nil
}

// DeriveSharedKey performs Diffie-Hellman key exchange and derives a symmetric key
func DeriveSharedKey(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != x25519.Size || len(peerPublicKey) != x25519.Size {
		return nil, fmt.Errorf("invalid key size")
	}

	var privKey, pubKey x25519.Key
	copy(privKey[:], privateKey)
	copy(pubKey[:], peerPublicKey)

	var sharedSecret x25519.Key
	x25519.Shared(&sharedSecret, &privKey, &pubKey)

	// Hash the shared secret to derive the symmetric key
	hash := sha256.Sum256(sharedSecret[:])
	return hash[:], nil
}

// EncryptPayload encrypts a payload using AES-GCM with the given key
func EncryptPayload(key []byte, plaintext []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate plaintext, prepending the nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptPayload decrypts a payload using AES-GCM with the given key
func DecryptPayload(key []byte, ciphertext []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Verify ciphertext is long enough
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// LayeredPayload defines the structure for data within an intermediate onion layer.
// It contains the ID of the next hop and the encrypted payload for that hop.
type LayeredPayload struct {
	NextHop peer.ID
	Payload []byte // This is the encrypted data for the *next* hop
}

// EncodeLayeredPayload serializes the LayeredPayload struct.
func EncodeLayeredPayload(lp *LayeredPayload) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(lp); err != nil {
		return nil, fmt.Errorf("failed to encode layered payload: %w", err)
	}
	return buf.Bytes(), nil
}

// DecodeLayeredPayload deserializes the LayeredPayload struct.
func DecodeLayeredPayload(data []byte) (*LayeredPayload, error) {
	var lp LayeredPayload
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&lp); err != nil {
		// Just return the error, the caller (handleRelayStream) will try DecodeInnerPayload next.
		return nil, fmt.Errorf("failed to decode as LayeredPayload: %w", err)
	}
	return &lp, nil
}

// CreateOnionLayers builds the layered encryption for an onion route.
// path: A slice of PeerIDs representing the relay nodes in order (e.g., [R1, R2, R3]).
// relayKeys: A slice of symmetric keys, one for each relay in the path (e.g., [K1, K2, K3]).
// finalRecipient: The PeerID of the final destination node (e.g., B). (Currently unused, assuming InnerPayload handles destination)
// innerPayloadBytes: The actual data payload for the final recipient.
func CreateOnionLayers(path []peer.ID, relayKeys [][]byte, finalRecipient peer.ID, innerPayloadBytes []byte) ([]byte, error) {
	if len(path) != len(relayKeys) {
		return nil, fmt.Errorf("path length (%d) must equal keys length (%d)", len(path), len(relayKeys))
	}
	if len(path) == 0 {
		// Direct connection? Or error? For onion routing, path shouldn't be empty.
		// If direct connection is allowed, encrypt directly for the recipient?
		// For now, assume onion routing requires at least one relay.
		return nil, fmt.Errorf("onion path cannot be empty")
	}

	// 1. Prepare the payload for the *last* relay (exit node).
	//    This payload, when decrypted by the exit node, should be the InnerPayload.
	lastRelayIndex := len(path) - 1
	payloadForExitNode := innerPayloadBytes // This is what the exit node should see after decryption.

	// 2. Encrypt this payload using the exit node's key.
	currentEncryptedPayload, err := EncryptPayload(relayKeys[lastRelayIndex], payloadForExitNode)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt exit layer %d: %w", lastRelayIndex, err)
	}

	// 3. Iterate backwards from the second-to-last relay to the first relay.
	for i := len(path) - 2; i >= 0; i-- {
		// Relay at index `i` needs to forward to relay at index `i+1`.
		nextHopID := path[i+1]

		// Create the structure that relay `i` will see after decrypting.
		// This structure tells relay `i` where to send the `currentEncryptedPayload`.
		payloadForRelayI := &LayeredPayload{
			NextHop: nextHopID,
			Payload: currentEncryptedPayload, // This is already encrypted for the *next* hop (i+1)
		}

		// Encode this structure.
		encodedPayloadForRelayI, err := EncodeLayeredPayload(payloadForRelayI)
		if err != nil {
			return nil, fmt.Errorf("failed to encode layered payload for hop %d: %w", i, err)
		}

		// Encrypt the encoded structure using the key for relay `i`.
		currentEncryptedPayload, err = EncryptPayload(relayKeys[i], encodedPayloadForRelayI)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt intermediate layer %d: %w", i, err)
		}
	}

	// The final currentEncryptedPayload is the fully wrapped onion to be sent to the first relay (path[0]).
	return currentEncryptedPayload, nil
}
