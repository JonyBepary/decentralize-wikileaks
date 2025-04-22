package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256" // Needed for standard marshalling format
	"encoding/pem"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/crypto"
	"golang.org/x/crypto/pbkdf2"
)

const (
	pemType          = "LIBP2P PRIVATE KEY"
	saltSize         = 16
	pbkdf2Iterations = 600000
	aesKeySize       = 32 // AES-256
)

// Libp2pCrypto implements KeyPairGenerator and KeySerializer using go-libp2p's crypto library.
type Libp2pCrypto struct{}

// NewLibp2pCrypto creates a new instance of Libp2pCrypto.
func NewLibp2pCrypto() *Libp2pCrypto {
	return &Libp2pCrypto{}
}

// --- KeyPairGenerator Implementation ---

// GenerateKeyPair creates a new cryptographic key pair using the specified type and bits.
func (lc *Libp2pCrypto) GenerateKeyPair(keyType int, bits int) (crypto.PrivKey, crypto.PubKey, error) {
	priv, pub, err := crypto.GenerateKeyPair(keyType, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("libp2p crypto failed to generate key pair: %w", err)
	}
	return priv, pub, nil
}

// --- KeySerializer Implementation ---

// MarshalEncryptPrivateKey serializes a private key and encrypts it with a password,
// returning a PEM block ready for storage.
func (lc *Libp2pCrypto) MarshalEncryptPrivateKey(privKey crypto.PrivKey, password string) (*pem.Block, error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty for encryption")
	}

	// 1. Marshal the private key to bytes (PKCS8 format is standard)
	// Note: go-libp2p's MarshalPrivateKey handles the different key types correctly.
	pkcs8Bytes, err := crypto.MarshalPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS8: %w", err)
	}

	// 2. Encrypt the bytes using the password
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive a key from the password using PBKDF2
	derivedKey := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// Encrypt using AES-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	encryptedBytes := gcm.Seal(nonce, nonce, pkcs8Bytes, nil) // Seal appends ciphertext to nonce

	// 3. Create the PEM block
	pemBlock := &pem.Block{
		Type: pemType,
		Headers: map[string]string{
			"Salt": fmt.Sprintf("%x", salt),
		},
		Bytes: encryptedBytes,
	}

	return pemBlock, nil
}

// DecryptUnmarshalPrivateKey decrypts a PEM block using a password and deserializes
// it back into a private key.
func (lc *Libp2pCrypto) DecryptUnmarshalPrivateKey(pemBlock *pem.Block, password string) (crypto.PrivKey, error) {
	if pemBlock == nil {
		return nil, fmt.Errorf("PEM block cannot be nil")
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty for decryption")
	}
	if pemBlock.Type != pemType {
		return nil, fmt.Errorf("unexpected PEM block type: expected %s, got %s", pemType, pemBlock.Type)
	}

	// 1. Retrieve salt and derive key
	saltHex, ok := pemBlock.Headers["Salt"]
	if !ok {
		return nil, fmt.Errorf("PEM header 'Salt' not found")
	}
	salt := make([]byte, saltSize)
	_, err := fmt.Sscanf(saltHex, "%x", &salt) // Simple hex decoding
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt from PEM header '%s': %w", saltHex, err)
	}

	derivedKey := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// 2. Decrypt the key bytes using AES-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(pemBlock.Bytes) < gcm.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext size")
	}
	nonce := pemBlock.Bytes[:gcm.NonceSize()]
	ciphertext := pemBlock.Bytes[gcm.NonceSize():]

	pkcs8Bytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Don't leak specifics, just indicate decryption failed (likely wrong password)
		return nil, fmt.Errorf("failed to decrypt key (incorrect password?)")
	}

	// 3. Unmarshal the decrypted bytes back into a libp2p private key
	privKey, err := crypto.UnmarshalPrivateKey(pkcs8Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted private key: %w", err)
	}

	return privKey, nil
}

// Ensure Libp2pCrypto satisfies the interfaces at compile time.
var _ KeyPairGenerator = (*Libp2pCrypto)(nil)
var _ KeySerializer = (*Libp2pCrypto)(nil)
