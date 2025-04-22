package ipfs

import (
	"context"
	"io"
)

// IPFSInteractor defines the interface for interacting with an IPFS node.
type IPFSInteractor interface {
	// AddData adds data to IPFS and returns its Content Identifier (CID).
	// The data is provided via an io.Reader.
	AddData(ctx context.Context, data io.Reader) (cid string, err error)

	// GetData retrieves data from IPFS using its CID.
	// Returns an io.ReadCloser containing the data. The caller is responsible
	// for closing the reader.
	GetData(ctx context.Context, cid string) (io.ReadCloser, error)

	// Close any underlying connections or clients.
	Close() error
}
