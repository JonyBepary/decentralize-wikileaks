package ipfs

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
	// We will need the go-ipfs-http-client library later
	// "github.com/ipfs/go-ipfs-http-client"
	// ma "github.com/multiformats/go-multiaddr"
)

// Default Kubo API address
const defaultKuboAPIMaddr = "/ip4/127.0.0.1/tcp/5001"

// TestKuboIPFSInteractor_AddData tests adding data to a local Kubo node.
// NOTE: This test requires a local Kubo daemon to be running and accessible
// at the defaultKuboAPIMaddr.
func TestKuboIPFSInteractor_AddData(t *testing.T) {
	// Skip test if Kubo isn't running? For now, assume it is.
	// A helper function could ping the API endpoint first.

	// Instantiate the KuboIPFSInteractor
	interactor, err := NewKuboIPFSInteractor(defaultKuboAPIMaddr)
	if err != nil {
		// Skip the test if we cannot create the interactor (likely daemon issue), log the exact error.
		t.Skipf("Skipping test: Failed to create KuboIPFSInteractor (daemon running?). Error: %v", err)
		// No need for Fatalf here, Skipf stops the test.
	}
	defer interactor.Close() // Ensure Close is called

	// Prepare sample data
	testData := "Hello IPFS via Kubo!"
	reader := strings.NewReader(testData)

	// Set a timeout for the context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // Generous timeout for IPFS ops
	defer cancel()

	// Call AddData
	cid, err := interactor.AddData(ctx, reader)

	// Assertions
	if err != nil {
		t.Fatalf("AddData failed unexpectedly: %v", err)
	}
	if cid == "" {
		t.Fatal("AddData returned an empty CID")
	}

	// Basic CID format check (starts with Qm for v0 or bafy for v1)
	if !strings.HasPrefix(cid, "Qm") && !strings.HasPrefix(cid, "bafy") {
		t.Errorf("AddData returned a CID with unexpected format: %s", cid)
	}

	t.Logf("Successfully added data, CID: %s", cid)

	// TODO: Add a subsequent GetData test to verify the content matches
}

// TestKuboIPFSInteractor_AddGetData_RoundTrip tests adding and then getting data.
// Requires a running Kubo daemon.
func TestKuboIPFSInteractor_AddGetData_RoundTrip(t *testing.T) {
	// Instantiate the KuboIPFSInteractor
	interactor, err := NewKuboIPFSInteractor(defaultKuboAPIMaddr)
	if err != nil {
		t.Skipf("Skipping test: Failed to create KuboIPFSInteractor (daemon running?). Error: %v", err)
	}
	defer interactor.Close()

	// Prepare sample data
	testData := "This is the data for the round trip test!"
	reader := strings.NewReader(testData)
	expectedBytes := []byte(testData) // Store expected bytes

	// Set a timeout for the context
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second) // Slightly longer for add + get
	defer cancel()

	// 1. Add Data
	cid, err := interactor.AddData(ctx, reader)
	if err != nil {
		t.Fatalf("RoundTrip AddData failed unexpectedly: %v", err)
	}
	if cid == "" {
		t.Fatal("RoundTrip AddData returned an empty CID")
	}
	t.Logf("RoundTrip added data, CID: %s", cid)

	// --- This is where the test will fail initially ---

	// 2. Get Data
	retrievedReader, err := interactor.GetData(ctx, cid)
	if err != nil {
		// Expecting "GetData not yet implemented" error initially
		t.Fatalf("RoundTrip GetData failed unexpectedly: %v", err)
	}
	if retrievedReader == nil {
		t.Fatal("RoundTrip GetData returned a nil reader")
	}
	defer retrievedReader.Close() // Ensure the reader is closed

	// 3. Verify Content
	retrievedBytes, err := io.ReadAll(retrievedReader)
	if err != nil {
		t.Fatalf("RoundTrip failed to read retrieved data: %v", err)
	}

	if !bytes.Equal(expectedBytes, retrievedBytes) {
		t.Errorf("RoundTrip retrieved data does not match original data.\nExpected: %s\nGot:      %s", string(expectedBytes), string(retrievedBytes))
	} else {
		t.Logf("RoundTrip successfully verified retrieved data.")
	}
}

// TODO: Add TestKuboIPFSInteractor_GetData
// TODO: Add TestKuboIPFSInteractor_AddGetData_RoundTrip
