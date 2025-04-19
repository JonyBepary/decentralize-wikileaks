package crypto

import (
	"crypto/rand"
	"fmt"

	base58 "github.com/mr-tron/base58" // Using base58 for user-friendly representation

	"github.com/cloudflare/circl/sign/ed25519"
)

// AccountID represents the public key part of the user's identity.
// Stored as a base58 encoded string for easier handling.
type AccountID string

// RecoveryPassword represents the private key part of the user's identity.
// Stored as a base58 encoded string. Should be kept secret by the user.
type RecoveryPassword string

// GenerateAccount creates a new Ed25519 key pair.
// It returns the public key as AccountID and the private key as RecoveryPassword.
func GenerateAccount() (AccountID, RecoveryPassword, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	// Encode keys to base58 for user-friendliness
	accountID := AccountID(base58.Encode(publicKey))
	recoveryPassword := RecoveryPassword(base58.Encode(privateKey)) // Includes public key, standard for ed25519

	return accountID, recoveryPassword, nil
}

// RestoreAccount derives the AccountID (public key) from a RecoveryPassword (private key).
func RestoreAccount(password RecoveryPassword) (AccountID, error) {
	privateKeyBytes, err := base58.Decode(string(password))
	if err != nil {
		return "", fmt.Errorf("failed to decode recovery password: %w", err)
	}

	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key length: expected %d, got %d", ed25519.PrivateKeySize, len(privateKeyBytes))
	}

	// In Ed25519, the private key contains the public key.
	// We extract the public key part.
	publicKeyBytes := privateKeyBytes[ed25519.PrivateKeySize-ed25519.PublicKeySize:]

	accountID := AccountID(base58.Encode(publicKeyBytes))
	return accountID, nil
}

// VerifySignature checks if a signature is valid for a given message and account ID.
func VerifySignature(id AccountID, message, signature []byte) (bool, error) {
	publicKeyBytes, err := base58.Decode(string(id))
	if err != nil {
		return false, fmt.Errorf("failed to decode account ID: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key length: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyBytes))
	}

	isValid := ed25519.Verify(publicKeyBytes, message, signature)
	return isValid, nil
}

// SignMessage signs a message using the private key derived from the recovery password.
func SignMessage(password RecoveryPassword, message []byte) ([]byte, error) {
	privateKeyBytes, err := base58.Decode(string(password))
	if err != nil {
		return nil, fmt.Errorf("failed to decode recovery password: %w", err)
	}
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", ed25519.PrivateKeySize, len(privateKeyBytes))
	}

	signature := ed25519.Sign(privateKeyBytes, message)
	return signature, nil
}

// GetPublicKeyBytes extracts the raw public key bytes from an AccountID.
func GetPublicKeyBytes(id AccountID) ([]byte, error) {
	publicKeyBytes, err := base58.Decode(string(id))
	if err != nil {
		return nil, fmt.Errorf("failed to decode account ID: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyBytes))
	}
	return publicKeyBytes, nil
}

// GetPrivateKeyBytes extracts the raw private key bytes from a RecoveryPassword.
func GetPrivateKeyBytes(password RecoveryPassword) ([]byte, error) {
	privateKeyBytes, err := base58.Decode(string(password))
	if err != nil {
		return nil, fmt.Errorf("failed to decode recovery password: %w", err)
	}
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", ed25519.PrivateKeySize, len(privateKeyBytes))
	}
	return privateKeyBytes, nil
}
