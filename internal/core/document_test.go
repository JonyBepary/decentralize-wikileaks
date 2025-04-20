package core

import (
	"bytes"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/jonybepary/decentralize-wikileaks/internal/crypto"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a dummy CID for testing
func createDummyCID(t *testing.T, content string) cid.Cid {
	t.Helper()
	h, err := multihash.Sum([]byte(content), multihash.SHA2_256, -1)
	require.NoError(t, err)
	return cid.NewCidV1(cid.Raw, h)
}

// Helper function to create and sign a document
func createTestDocument(t *testing.T, authorID crypto.AccountID, recoveryPassword crypto.RecoveryPassword, contentCID cid.Cid, previousCID *cid.Cid) *Document {
	t.Helper()
	doc := &Document{
		AuthorID:    authorID,
		Timestamp:   time.Now().UTC().Truncate(time.Millisecond), // Truncate for consistent comparison
		ContentCID:  contentCID,
		PreviousCID: previousCID,
	}

	bytesToSign, err := doc.BytesToSign()
	require.NoError(t, err)

	signature, err := crypto.SignMessage(recoveryPassword, bytesToSign)
	require.NoError(t, err)
	doc.Signature = signature

	return doc
}

func TestDocumentToFromNode(t *testing.T) {
	authorID, recoveryPassword, err := crypto.GenerateAccount()
	require.NoError(t, err)

	contentCID := createDummyCID(t, "dummy content")
	originalDoc := createTestDocument(t, authorID, recoveryPassword, contentCID, nil)

	node, err := originalDoc.ToNode()
	require.NoError(t, err)
	require.NotNil(t, node)

	decodedDoc, err := DocumentFromNode(node)
	require.NoError(t, err)
	require.NotNil(t, decodedDoc)

	assert.Equal(t, originalDoc.AuthorID, decodedDoc.AuthorID)
	assert.True(t, originalDoc.Timestamp.Equal(decodedDoc.Timestamp))
	assert.Equal(t, originalDoc.ContentCID, decodedDoc.ContentCID)
	assert.Equal(t, originalDoc.Signature, decodedDoc.Signature)
	assert.Nil(t, decodedDoc.PreviousCID) // Original had nil PreviousCID
}

func TestDocumentToFromNodeWithPrevious(t *testing.T) {
	authorID, recoveryPassword, err := crypto.GenerateAccount()
	require.NoError(t, err)

	prevCID := createDummyCID(t, "previous content")
	contentCID := createDummyCID(t, "current content")
	originalDoc := createTestDocument(t, authorID, recoveryPassword, contentCID, &prevCID)

	node, err := originalDoc.ToNode()
	require.NoError(t, err)

	decodedDoc, err := DocumentFromNode(node)
	require.NoError(t, err)
	require.NotNil(t, decodedDoc)

	assert.Equal(t, originalDoc.AuthorID, decodedDoc.AuthorID)
	assert.True(t, originalDoc.Timestamp.Equal(decodedDoc.Timestamp))
	assert.Equal(t, originalDoc.ContentCID, decodedDoc.ContentCID)
	assert.Equal(t, originalDoc.Signature, decodedDoc.Signature)
	require.NotNil(t, decodedDoc.PreviousCID)
	assert.Equal(t, *originalDoc.PreviousCID, *decodedDoc.PreviousCID)
}

func TestDocumentGetCID(t *testing.T) {
	authorID, recoveryPassword, err := crypto.GenerateAccount()
	require.NoError(t, err)

	contentCID1 := createDummyCID(t, "content 1")
	contentCID2 := createDummyCID(t, "content 2")

	doc1 := createTestDocument(t, authorID, recoveryPassword, contentCID1, nil)
	doc1Copy := createTestDocument(t, authorID, recoveryPassword, contentCID1, nil)
	doc1Copy.Timestamp = doc1.Timestamp // Ensure timestamp is identical for copy
	doc1Copy.Signature = doc1.Signature // Ensure signature is identical

	doc2 := createTestDocument(t, authorID, recoveryPassword, contentCID2, nil)

	cid1, err := doc1.GetCID()
	require.NoError(t, err)
	assert.NotEqual(t, cid.Undef, cid1)

	cid1Copy, err := doc1Copy.GetCID()
	require.NoError(t, err)
	assert.Equal(t, cid1, cid1Copy, "Identical documents should have the same CID")

	cid2, err := doc2.GetCID()
	require.NoError(t, err)
	assert.NotEqual(t, cid.Undef, cid2)
	assert.NotEqual(t, cid1, cid2, "Different documents should have different CIDs")
}

func TestDocumentSignVerify(t *testing.T) {
	authorID, recoveryPassword, err := crypto.GenerateAccount()
	require.NoError(t, err)

	otherAuthorID, _, err := crypto.GenerateAccount()
	require.NoError(t, err)

	contentCID := createDummyCID(t, "sign verify content")
	doc := createTestDocument(t, authorID, recoveryPassword, contentCID, nil)

	// Test valid signature
	valid, err := doc.Verify()
	require.NoError(t, err)
	assert.True(t, valid, "Signature should be valid")

	// Test invalid signature (tampered content - simulate by changing CID)
	originalContentCID := doc.ContentCID
	doc.ContentCID = createDummyCID(t, "tampered content")
	valid, err = doc.Verify()
	require.NoError(t, err) // Verification itself shouldn't error, just return false
	assert.False(t, valid, "Signature should be invalid after content CID change")
	doc.ContentCID = originalContentCID // Restore for next test

	// Test invalid signature (wrong author)
	originalAuthorID := doc.AuthorID
	doc.AuthorID = otherAuthorID
	valid, err = doc.Verify()
	// require.Error(t, err) // Decoding the original author's pubkey from the new ID will fail - INCORRECT ASSUMPTION
	require.NoError(t, err) // Verification with a different valid key should not error
	assert.False(t, valid, "Signature should be invalid when checked against wrong author ID")
	doc.AuthorID = originalAuthorID // Restore

	// Test invalid signature (signature itself is wrong)
	originalSignature := doc.Signature
	doc.Signature = []byte("invalid signature data")
	valid, err = doc.Verify()
	require.NoError(t, err) // Verification itself shouldn't error
	assert.False(t, valid, "Signature should be invalid with incorrect signature data")
	doc.Signature = originalSignature // Restore
}

func TestDocumentEncodeDecode(t *testing.T) {
	authorID, recoveryPassword, err := crypto.GenerateAccount()
	require.NoError(t, err)

	contentCID := createDummyCID(t, "encode decode content")
	originalDoc := createTestDocument(t, authorID, recoveryPassword, contentCID, nil)

	node, err := originalDoc.ToNode()
	require.NoError(t, err)

	encodedBytes, err := EncodeNode(node)
	require.NoError(t, err)
	require.NotEmpty(t, encodedBytes)

	decodedNode, err := DecodeNode(encodedBytes)
	require.NoError(t, err)
	require.NotNil(t, decodedNode)

	decodedDoc, err := DocumentFromNode(decodedNode)
	require.NoError(t, err)

	assert.Equal(t, originalDoc.AuthorID, decodedDoc.AuthorID)
	assert.True(t, originalDoc.Timestamp.Equal(decodedDoc.Timestamp))
	assert.Equal(t, originalDoc.ContentCID, decodedDoc.ContentCID)
	assert.Equal(t, originalDoc.Signature, decodedDoc.Signature)
	assert.Nil(t, decodedDoc.PreviousCID)
}

// Test that BytesToSign is deterministic
func TestBytesToSignDeterminism(t *testing.T) {
	authorID, recoveryPassword, err := crypto.GenerateAccount()
	require.NoError(t, err)
	contentCID := createDummyCID(t, "deterministic content")

	doc1 := createTestDocument(t, authorID, recoveryPassword, contentCID, nil)
	// Create a second doc with the same relevant fields
	doc2 := &Document{
		AuthorID:   doc1.AuthorID,
		Timestamp:  doc1.Timestamp,
		ContentCID: doc1.ContentCID,
		// Signature and PreviousCID are not part of BytesToSign
	}

	bytes1, err := doc1.BytesToSign()
	require.NoError(t, err)

	bytes2, err := doc2.BytesToSign()
	require.NoError(t, err)

	assert.True(t, bytes.Equal(bytes1, bytes2), "BytesToSign should be deterministic")
}
