package identity

import (
	"testing"
)

// TestGenerateKeyPair checks if a valid key pair can be generated.
// It expects a non-nil private key and a non-nil public key.
func TestGenerateKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateKeyPair() // This function doesn't exist yet

	if err != nil {
		t.Fatalf("GenerateKeyPair() returned an error: %v", err)
	}

	if privKey == nil {
		t.Error("GenerateKeyPair() returned a nil private key")
	}

	if pubKey == nil {
		t.Error("GenerateKeyPair() returned a nil public key")
	}

	// TODO: Add more checks later, e.g., key type, public key derivation from private key.
}

// TestSaveLoadPrivateKey checks if a private key can be saved to a file
// and loaded back correctly.
func TestSaveLoadPrivateKey(t *testing.T) {
	// 1. Generate a key pair first
	privKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Prerequisite GenerateKeyPair() failed: %v", err)
	}
	if privKey == nil {
		t.Fatal("Prerequisite GenerateKeyPair() returned nil private key")
	}

	// 2. Define a temporary file path for saving
	// Use t.TempDir() to create a temporary directory that gets cleaned up automatically
	tempDir := t.TempDir()
	filePath := tempDir + "/test_priv_key.pem" // Example path
	password := "verysecretpassword"           // Example password

	// 3. Save the private key (function doesn't exist yet)
	err = SavePrivateKey(privKey, filePath, password)
	if err != nil {
		t.Fatalf("SavePrivateKey() returned an error: %v", err)
	}

	// 4. Load the private key back (function doesn't exist yet)
	loadedPrivKey, err := LoadPrivateKey(filePath, password)
	if err != nil {
		t.Fatalf("LoadPrivateKey() returned an error: %v", err)
	}

	// 5. Verify the loaded key matches the original key
	if loadedPrivKey == nil {
		t.Fatal("LoadPrivateKey() returned a nil private key")
	}

	// Use the Equals method provided by the crypto interface
	if !privKey.Equals(loadedPrivKey) {
		t.Errorf("Loaded private key does not match the original private key")
	}

	// Optional: Verify the public keys also match
	if !privKey.GetPublic().Equals(loadedPrivKey.GetPublic()) {
		t.Errorf("Public key derived from loaded private key does not match original public key")
	}
}
