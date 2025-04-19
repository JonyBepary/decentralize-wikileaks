package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateAccount(t *testing.T) {
	accountID, recoveryPassword, err := GenerateAccount()
	if err != nil {
		t.Fatalf("GenerateAccount() error = %v", err)
	}

	if accountID == "" {
		t.Error("GenerateAccount() returned empty AccountID")
	}
	if recoveryPassword == "" {
		t.Error("GenerateAccount() returned empty RecoveryPassword")
	}

	// Basic check: Try decoding to ensure they are valid base58
	_, err = GetPublicKeyBytes(accountID)
	if err != nil {
		t.Errorf("Generated AccountID is not valid base58: %v", err)
	}
	_, err = GetPrivateKeyBytes(recoveryPassword)
	if err != nil {
		t.Errorf("Generated RecoveryPassword is not valid base58: %v", err)
	}
	t.Logf("Generated AccountID: %s", accountID)
	t.Logf("Generated RecoveryPassword: %s", recoveryPassword)
}

func TestRestoreAccount(t *testing.T) {
	originalAccountID, recoveryPassword, err := GenerateAccount()
	if err != nil {
		t.Fatalf("Setup failed: GenerateAccount() error = %v", err)
	}

	restoredAccountID, err := RestoreAccount(recoveryPassword)
	if err != nil {
		t.Fatalf("RestoreAccount() error = %v", err)
	}

	if restoredAccountID != originalAccountID {
		t.Errorf("RestoreAccount() = %v, want %v", restoredAccountID, originalAccountID)
	}

	// Test invalid password
	_, err = RestoreAccount(RecoveryPassword("invalid-base58-string!@#"))
	if err == nil {
		t.Error("RestoreAccount() with invalid password did not return an error")
	}
}

func TestSignAndVerify(t *testing.T) {
	accountID, recoveryPassword, err := GenerateAccount()
	if err != nil {
		t.Fatalf("Setup failed: GenerateAccount() error = %v", err)
	}

	message := []byte("This is a secret message.")

	signature, err := SignMessage(recoveryPassword, message)
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("SignMessage() returned empty signature")
	}

	// Test valid signature
	valid, err := VerifySignature(accountID, message, signature)
	if err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	if !valid {
		t.Error("VerifySignature() returned false for a valid signature")
	}

	// Test invalid signature (tampered message)
	tamperedMessage := []byte("This is NOT the secret message.")
	valid, err = VerifySignature(accountID, tamperedMessage, signature)
	if err != nil {
		t.Fatalf("VerifySignature() with tampered message error = %v", err)
	}
	if valid {
		t.Error("VerifySignature() returned true for a tampered message")
	}

	// Test invalid signature (wrong public key)
	otherAccountID, _, err := GenerateAccount()
	if err != nil {
		t.Fatalf("Setup failed: GenerateAccount() for other key error = %v", err)
	}
	valid, err = VerifySignature(otherAccountID, message, signature)
	if err != nil {
		t.Fatalf("VerifySignature() with wrong public key error = %v", err)
	}
	if valid {
		t.Error("VerifySignature() returned true for a wrong public key")
	}
}

func TestGetPublicKeyBytes(t *testing.T) {
	accountID, _, err := GenerateAccount()
	if err != nil {
		t.Fatalf("Setup failed: GenerateAccount() error = %v", err)
	}

	pkBytes, err := GetPublicKeyBytes(accountID)
	if err != nil {
		t.Fatalf("GetPublicKeyBytes() error = %v", err)
	}
	if len(pkBytes) != 32 { // ed25519.PublicKeySize is 32
		t.Errorf("GetPublicKeyBytes() returned %d bytes, want 32", len(pkBytes))
	}

	// Test invalid input
	_, err = GetPublicKeyBytes(AccountID("invalid-base58!@#"))
	if err == nil {
		t.Error("GetPublicKeyBytes() with invalid base58 did not return an error")
	}
}

func TestGetPrivateKeyBytes(t *testing.T) {
	_, recoveryPassword, err := GenerateAccount()
	if err != nil {
		t.Fatalf("Setup failed: GenerateAccount() error = %v", err)
	}

	skBytes, err := GetPrivateKeyBytes(recoveryPassword)
	if err != nil {
		t.Fatalf("GetPrivateKeyBytes() error = %v", err)
	}
	if len(skBytes) != 64 { // ed25519.PrivateKeySize is 64
		t.Errorf("GetPrivateKeyBytes() returned %d bytes, want 64", len(skBytes))
	}

	// Verify that the last 32 bytes of the private key match the public key
	accountID, err := RestoreAccount(recoveryPassword)
	if err != nil {
		t.Fatalf("RestoreAccount failed: %v", err)
	}
	pkBytes, err := GetPublicKeyBytes(accountID)
	if err != nil {
		t.Fatalf("GetPublicKeyBytes failed: %v", err)
	}

	if !bytes.Equal(skBytes[32:], pkBytes) {
		t.Error("Private key's suffix does not match the derived public key")
	}

	// Test invalid input
	_, err = GetPrivateKeyBytes(RecoveryPassword("invalid-base58!@#"))
	if err == nil {
		t.Error("GetPrivateKeyBytes() with invalid base58 did not return an error")
	}
}
