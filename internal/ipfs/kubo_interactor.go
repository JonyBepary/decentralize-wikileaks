package ipfs

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	files "github.com/ipfs/boxo/files"
	"github.com/ipfs/boxo/path" // Import boxo/path
	"github.com/ipfs/go-cid"
	rpc "github.com/ipfs/kubo/client/rpc" // Use client from kubo repo
	ma "github.com/multiformats/go-multiaddr"
)

// KuboIPFSInteractor implements the IPFSInteractor interface using the Kubo RPC client library.
type KuboIPFSInteractor struct {
	client  *rpc.HttpApi
	apiAddr ma.Multiaddr
}

// NewKuboIPFSInteractor creates a new interactor connected to the specified Kubo API multiaddr.
func NewKuboIPFSInteractor(apiMaddrStr string) (*KuboIPFSInteractor, error) {
	if apiMaddrStr == "" {
		return nil, fmt.Errorf("Kubo API multiaddr string cannot be empty")
	}

	addr, err := ma.NewMultiaddr(apiMaddrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Kubo API multiaddr '%s': %w", apiMaddrStr, err)
	}

	// Create the RPC client instance using the multiaddr directly
	client, err := rpc.NewApi(addr) // Use NewApi which accepts multiaddr
	if err != nil {
		// Check for connection refused specifically, return error for test skipping
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "context deadline exceeded") {
			return nil, fmt.Errorf("failed to create IPFS RPC client for '%s' (connection issue): %w", apiMaddrStr, err)
		}
		return nil, fmt.Errorf("failed to create IPFS RPC client for '%s' (unexpected error): %w", apiMaddrStr, err)
	}

	// Verify connectivity by sending an "id" request
	idCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := client.Request("id")         // Build the "id" request
	var idOutput map[string]interface{} // Expecting a map[string]interface{} or specific struct? Let's use map for now.
	err = req.Exec(idCtx, &idOutput)    // Execute and decode response into idOutput
	if err != nil {
		// Check specifically for connection errors that might still occur here
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "context deadline exceeded") {
			return nil, fmt.Errorf("failed to connect to Kubo API at '%s' (connection issue): %w", apiMaddrStr, err)
		}
		// Any other error during ID fetch is also a problem
		return nil, fmt.Errorf("failed to execute 'id' command via Kubo API at '%s': %w", apiMaddrStr, err)
	}
	// Optionally, check the output contains an "ID" field
	peerID, ok := idOutput["ID"].(string)
	if !ok || peerID == "" {
		fmt.Printf("Warning: 'id' command executed but did not return an ID string as expected. Output: %v\n", idOutput)
		// Continue anyway, as the command execution itself succeeded.
	} else {
		fmt.Printf("Successfully connected to IPFS node %s at %s\n", peerID, apiMaddrStr)
	}
	return &KuboIPFSInteractor{
		client:  client,
		apiAddr: addr,
	}, nil
}

// AddData adds data via the Kubo RPC client.
func (k *KuboIPFSInteractor) AddData(ctx context.Context, data io.Reader) (cidStr string, err error) {
	// Wrap reader using boxo/files
	fileReader := files.NewReaderFile(data)

	// Use the Add method from the Unixfs API part of the RPC client
	resolvedPath, err := k.client.Unixfs().Add(ctx, fileReader) // Use k.client
	if err != nil {
		return "", fmt.Errorf("kubo RPC client failed to add data: %w", err)
	}

	// The CID is the root CID of the resolved path
	cid := resolvedPath.RootCid() // Use RootCid()
	if !cid.Defined() {
		return "", fmt.Errorf("kubo RPC client Add returned an undefined RootCid in path %s", resolvedPath.String())
	}

	return cid.String(), nil
}

// GetData retrieves data via the Kubo RPC client.
// --- ONLY ONE DEFINITION OF THIS FUNCTION ---
func (k *KuboIPFSInteractor) GetData(ctx context.Context, cidStr string) (io.ReadCloser, error) {
	// Parse the CID string
	dataCid, err := cid.Decode(cidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CID string '%s': %w", cidStr, err)
	}

	// Create a path object from the CID using boxo/path
	p := path.FromCid(dataCid) // Use path.FromCid

	// Get a file descriptor using the Unixfs Get method
	node, err := k.client.Unixfs().Get(ctx, p) // Get takes a path.Path
	if err != nil {
		return nil, fmt.Errorf("kubo RPC client failed to get data for CID '%s': %w", cidStr, err)
	}

	// Ensure the node is a file and get its reader
	fileNode, ok := node.(files.File)
	if !ok {
		// Close if it's not a file (files.Node implements io.Closer)
		if closer, ok := node.(io.Closer); ok {
			closer.Close()
		}
		return nil, fmt.Errorf("retrieved node for CID '%s' is not a file", cidStr)
	}

	// The files.File itself is an io.ReadCloser
	return fileNode, nil
}

// --- END OF GetData FUNCTION ---

// Close is a no-op for the RPC client's default http client.
func (k *KuboIPFSInteractor) Close() error {
	fmt.Println("KuboIPFSInteractor: Close() called (no-op for RPC client's underlying http client)")
	return nil
}

// Compile-time check to ensure KuboIPFSInteractor implements IPFSInteractor
var _ IPFSInteractor = (*KuboIPFSInteractor)(nil)
