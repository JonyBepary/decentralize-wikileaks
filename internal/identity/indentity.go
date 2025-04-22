package identity

import (
	"encoding/pem" // Needed for file I/O part
	"fmt"
	"os"

	"github.com/jonybepary/decentralize-wikileaks/internal/crypto" // Adjust import path if needed
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

// GenerateKeyPair creates a new cryptographic key pair suitable for a libp2p peer ID.
// It currently defaults to using Ed25519 keys via the crypto abstraction.
func GenerateKeyPair() (libp2pcrypto.PrivKey, libp2pcrypto.PubKey, error) {
	var generator crypto.KeyPairGenerator = crypto.NewLibp2pCrypto()
	priv, pub, err := generator.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		return nil, nil, fmt.Errorf("identity generation failed: %w", err)
	}
	return priv, pub, nil
}

// SavePrivateKey saves a libp2p private key to a file, encrypted with a password.
// It uses the crypto.KeySerializer for encryption and PEM block creation.
func SavePrivateKey(privKey libp2pcrypto.PrivKey, filePath string, password string) error {
	if filePath == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Get a KeySerializer instance
	var serializer crypto.KeySerializer = crypto.NewLibp2pCrypto()

	// Use the serializer to marshal and encrypt the key into a PEM block
	pemBlock, err := serializer.MarshalEncryptPrivateKey(privKey, password)
	if err != nil {
		// Error already has context from the serializer
		return fmt.Errorf("failed to prepare key for saving: %w", err)
	}

	// Write the PEM block to the file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		// Explicitly remove the file if encoding fails? Maybe not, partial write might be worse.
		return fmt.Errorf("failed to write PEM data to file %s: %w", filePath, err)
	}

	// Set file permissions (e.g., read/write for owner only)
	if err := os.Chmod(filePath, 0600); err != nil {
		// Log this error? It's not fatal to the save operation itself.
		fmt.Fprintf(os.Stderr, "Warning: failed to set permissions on %s: %v\n", filePath, err)
	}

	return nil
}

// LoadPrivateKey loads a libp2p private key from a file, decrypting it with a password.
// It uses the crypto.KeySerializer for decryption and unmarshalling.
func LoadPrivateKey(filePath string, password string) (libp2pcrypto.PrivKey, error) {
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// 1. Read the PEM file content
	pemData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", filePath, err)
	}

	// 2. Decode the PEM block
	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block from file %s", filePath)
	}

	// 3. Get a KeySerializer instance
	var serializer crypto.KeySerializer = crypto.NewLibp2pCrypto()

	// 4. Use the serializer to decrypt and unmarshal the key
	privKey, err := serializer.DecryptUnmarshalPrivateKey(pemBlock, password)
	if err != nil {
		// Error already has context from the serializer
		return nil, fmt.Errorf("failed to load key from %s: %w", filePath, err)
	}

	return privKey, nil
}
