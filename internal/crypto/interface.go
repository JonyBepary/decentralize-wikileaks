package crypto

import (
	"encoding/pem" // Import pem package

	"github.com/libp2p/go-libp2p/core/crypto"
)

// KeyPairGenerator defines the interface for generating cryptographic key pairs.
type KeyPairGenerator interface {
	// GenerateKeyPair creates a new cryptographic key pair.
	// KeyType specifies the desired algorithm (e.g., crypto.Ed25519, crypto.RSA).
	// Bits specifies the key size (e.g., 2048 for RSA, -1 for Ed25519).
	GenerateKeyPair(keyType int, bits int) (crypto.PrivKey, crypto.PubKey, error)
}

// --- NEW INTERFACE BELOW ---

// KeySerializer defines the interface for securely serializing and deserializing private keys.
type KeySerializer interface {
	// MarshalEncryptPrivateKey serializes a private key and encrypts it with a password,
	// returning a PEM block ready for storage.
	MarshalEncryptPrivateKey(privKey crypto.PrivKey, password string) (*pem.Block, error)

	// DecryptUnmarshalPrivateKey decrypts a PEM block using a password and deserializes
	// it back into a private key.
	DecryptUnmarshalPrivateKey(pemBlock *pem.Block, password string) (crypto.PrivKey, error)
}
