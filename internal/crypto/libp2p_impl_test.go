package crypto

import (
	// For comparing PEM blocks later if needed
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// TestLibp2pCrypto_GenerateKeyPair tests the key generation part.
// Although indirectly tested via identity tests, direct tests are good practice.
func TestLibp2pCrypto_GenerateKeyPair(t *testing.T) {
	lc := NewLibp2pCrypto()

	// Test Ed25519
	privEd, pubEd, errEd := lc.GenerateKeyPair(crypto.Ed25519, -1)
	if errEd != nil {
		t.Fatalf("GenerateKeyPair(Ed25519) failed: %v", errEd)
	}
	if privEd == nil || pubEd == nil {
		t.Fatal("GenerateKeyPair(Ed25519) returned nil key(s)")
	}
	if privEd.Type() != crypto.Ed25519 {
		t.Errorf("Expected Ed25519 key, got %v", privEd.Type())
	}
	if !pubEd.Equals(privEd.GetPublic()) {
		t.Error("Ed25519 public key does not match derived public key")
	}

	// Test RSA (example size)
	privRSA, pubRSA, errRSA := lc.GenerateKeyPair(crypto.RSA, 2048)
	if errRSA != nil {
		t.Fatalf("GenerateKeyPair(RSA) failed: %v", errRSA)
	}
	if privRSA == nil || pubRSA == nil {
		t.Fatal("GenerateKeyPair(RSA) returned nil key(s)")
	}
	if privRSA.Type() != crypto.RSA {
		t.Errorf("Expected RSA key, got %v", privRSA.Type())
	}
	if !pubRSA.Equals(privRSA.GetPublic()) {
		t.Error("RSA public key does not match derived public key")
	}
}

// TestLibp2pCrypto_KeySerializer_RoundTrip tests the Marshal/Encrypt and Decrypt/Unmarshal cycle.
func TestLibp2pCrypto_KeySerializer_RoundTrip(t *testing.T) {
	lc := NewLibp2pCrypto()
	password := "strongpassword123"

	// 1. Generate a test key pair (e.g., Ed25519)
	originalPrivKey, _, err := lc.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("Failed to generate key pair for test: %v", err)
	}

	// 2. Marshal and Encrypt the private key
	pemBlock, err := lc.MarshalEncryptPrivateKey(originalPrivKey, password)
	if err != nil {
		t.Fatalf("MarshalEncryptPrivateKey failed: %v", err)
	}
	if pemBlock == nil {
		t.Fatal("MarshalEncryptPrivateKey returned nil PEM block")
	}
	if pemBlock.Type != pemType { // Assuming pemType is accessible or redefined for test
		t.Errorf("Expected PEM block type %s, got %s", pemType, pemBlock.Type)
	}
	if len(pemBlock.Bytes) == 0 {
		t.Error("PEM block bytes are empty")
	}
	if _, ok := pemBlock.Headers["Salt"]; !ok {
		t.Error("PEM block header 'Salt' is missing")
	}

	// 3. Decrypt and Unmarshal the private key
	loadedPrivKey, err := lc.DecryptUnmarshalPrivateKey(pemBlock, password)
	if err != nil {
		t.Fatalf("DecryptUnmarshalPrivateKey failed: %v", err)
	}

	// 4. Verify the loaded key matches the original
	if loadedPrivKey == nil {
		t.Fatal("DecryptUnmarshalPrivateKey returned nil key")
	}
	if !originalPrivKey.Equals(loadedPrivKey) {
		t.Errorf("Decrypted key does not match original key.\nOriginal: %v\nLoaded:   %v", originalPrivKey, loadedPrivKey)
	}

	// 5. Test with incorrect password
	_, err = lc.DecryptUnmarshalPrivateKey(pemBlock, "wrongpassword")
	if err == nil {
		t.Error("DecryptUnmarshalPrivateKey should have failed with wrong password, but didn't")
	}
	// Optionally check the specific error message if the implementation provides a consistent one
	t.Logf("Successfully failed decryption with wrong password (expected error): %v", err)

	// 6. Test edge cases (nil key, empty password) for MarshalEncryptPrivateKey
	_, err = lc.MarshalEncryptPrivateKey(nil, password)
	if err == nil {
		t.Error("MarshalEncryptPrivateKey should fail with nil key")
	}
	_, err = lc.MarshalEncryptPrivateKey(originalPrivKey, "")
	if err == nil {
		t.Error("MarshalEncryptPrivateKey should fail with empty password")
	}

	// 7. Test edge cases (nil block, empty password) for DecryptUnmarshalPrivateKey
	_, err = lc.DecryptUnmarshalPrivateKey(nil, password)
	if err == nil {
		t.Error("DecryptUnmarshalPrivateKey should fail with nil PEM block")
	}
	_, err = lc.DecryptUnmarshalPrivateKey(pemBlock, "")
	if err == nil {
		t.Error("DecryptUnmarshalPrivateKey should fail with empty password")
	}
}

// TODO: Consider adding tests for different key types (RSA) in the round trip.
// TODO: Consider adding tests for malformed PEM blocks if necessary.
