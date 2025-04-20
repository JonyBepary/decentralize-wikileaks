package core

import (
	"time"

	"github.com/ipfs/go-cid"
	"github.com/jonybepary/decentralize-wikileaks/internal/crypto"

	// IPLD libraries for encoding/decoding and linking
	"bytes"
	"fmt"

	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
)

// Document represents a single piece of content published on the platform.
// It uses IPLD for its structure and linking.
type Document struct {
	AuthorID    crypto.AccountID // Author's public key identifier
	Timestamp   time.Time        // Time of creation/publication
	ContentCID  cid.Cid          // CID link to the actual content data (e.g., text, file)
	Signature   []byte           // Author's signature over AuthorID+Timestamp+ContentCID
	PreviousCID *cid.Cid         // Optional CID link to a previous version of this document
	// Add other fields as needed, e.g., Title, Tags, References []cid.Cid
}

// LinkSystem is a basic IPLD link system using CID links.
// In a real application, this would be configured with a blockstore (storage).
var LinkSystem = cidlink.DefaultLinkSystem()

// ToNode converts the Document struct into an IPLD Node.
func (d *Document) ToNode() (ipld.Node, error) {
	nb := basicnode.Prototype.Any.NewBuilder()
	ma, err := nb.BeginMap(5) // Adjust size based on the number of fields
	if err != nil {
		return nil, err
	}

	if err := ma.AssembleKey().AssignString("authorID"); err != nil {
		return nil, err
	}
	if err := ma.AssembleValue().AssignString(string(d.AuthorID)); err != nil {
		return nil, err
	}

	if err := ma.AssembleKey().AssignString("timestamp"); err != nil {
		return nil, err
	}
	// Store timestamp as ISO8601 string for better interoperability
	if err := ma.AssembleValue().AssignString(d.Timestamp.UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}

	if err := ma.AssembleKey().AssignString("contentCID"); err != nil {
		return nil, err
	}
	if err := ma.AssembleValue().AssignLink(cidlink.Link{Cid: d.ContentCID}); err != nil {
		return nil, err
	}

	if err := ma.AssembleKey().AssignString("signature"); err != nil {
		return nil, err
	}
	if err := ma.AssembleValue().AssignBytes(d.Signature); err != nil {
		return nil, err
	}

	if err := ma.AssembleKey().AssignString("previousCID"); err != nil {
		return nil, err
	}
	if d.PreviousCID != nil {
		if err := ma.AssembleValue().AssignLink(cidlink.Link{Cid: *d.PreviousCID}); err != nil {
			return nil, err
		}
	} else {
		if err := ma.AssembleValue().AssignNull(); err != nil {
			return nil, err
		}
	}

	if err := ma.Finish(); err != nil {
		return nil, err
	}

	return nb.Build(), nil
}

// FromNode populates a Document struct from an IPLD Node.
func DocumentFromNode(node ipld.Node) (*Document, error) {
	d := &Document{}

	if node.Kind() != ipld.Kind_Map {
		return nil, fmt.Errorf("expected map node, got %s", node.Kind())
	}

	authorNode, err := node.LookupByString("authorID")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup authorID: %w", err)
	}
	authorStr, err := authorNode.AsString()
	if err != nil {
		return nil, fmt.Errorf("failed to read authorID as string: %w", err)
	}
	d.AuthorID = crypto.AccountID(authorStr)

	timestampNode, err := node.LookupByString("timestamp")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup timestamp: %w", err)
	}
	timestampStr, err := timestampNode.AsString()
	if err != nil {
		return nil, fmt.Errorf("failed to read timestamp as string: %w", err)
	}
	d.Timestamp, err = time.Parse(time.RFC3339Nano, timestampStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp string: %w", err)
	}

	contentCIDNode, err := node.LookupByString("contentCID")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup contentCID: %w", err)
	}
	contentLink, err := contentCIDNode.AsLink()
	if err != nil {
		return nil, fmt.Errorf("failed to read contentCID as link: %w", err)
	}
	d.ContentCID = contentLink.(cidlink.Link).Cid

	signatureNode, err := node.LookupByString("signature")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup signature: %w", err)
	}
	d.Signature, err = signatureNode.AsBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to read signature as bytes: %w", err)
	}

	previousCIDNode, err := node.LookupByString("previousCID")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup previousCID: %w", err)
	}
	if previousCIDNode.Kind() == ipld.Kind_Link {
		previousLink, err := previousCIDNode.AsLink()
		if err != nil {
			return nil, fmt.Errorf("failed to read previousCID as link: %w", err)
		}
		prevCid := previousLink.(cidlink.Link).Cid
		d.PreviousCID = &prevCid
	} else if previousCIDNode.Kind() != ipld.Kind_Null {
		return nil, fmt.Errorf("expected previousCID to be link or null, got %s", previousCIDNode.Kind())
	}

	return d, nil
}

// GetCID calculates the CID of the Document node.
// This requires encoding the node first.
func (d *Document) GetCID() (cid.Cid, error) {
	node, err := d.ToNode()
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to convert document to node: %w", err)
	}

	// Encode the node to bytes using DAG-JSON
	encodedBytes, err := EncodeNode(node)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to encode node for CID calculation: %w", err)
	}

	// Define the CID Prefix (using DagJSON and SHA2-256)
	prefix := cid.Prefix{
		Version:  1,
		Codec:    cid.DagJSON,
		MhType:   0x12, // sha2-256
		MhLength: -1,   // default length
	}

	// Calculate the CID by hashing the encoded bytes
	calculatedCid, err := prefix.Sum(encodedBytes)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to calculate CID from encoded bytes: %w", err)
	}

	return calculatedCid, nil

	/* --- OLD LinkSystem.Store approach - requires blockstore ---
	// Store the node using the link system to generate the CID.
	// We use DAG-JSON here, but DAG-CBOR is often preferred for efficiency.
	// A real implementation needs a blockstore passed to the LinkSystem.
	lnk, err := LinkSystem.Store(ipld.LinkContext{}, cidlink.LinkPrototype{Prefix: cid.Prefix{ // Use default CID settings (sha2-256, dag-json)
		Version: 1,
		Codec:   cid.DagJSON,
		MhType:  0x12, // sha2-256
		MhLength: -1, // default length
	}}, node)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to store node and generate CID: %w", err)
	}

	return lnk.(cidlink.Link).Cid, nil
	*/
}

// BytesToSign returns the canonical byte representation of the document fields
// that should be signed by the author.
func (d *Document) BytesToSign() ([]byte, error) {
	// We need a consistent, canonical representation.
	// Re-encoding specific fields is one way.
	// A simpler approach for now: concatenate critical fields.
	// WARNING: This is a basic example; canonical serialization is crucial for security.
	var buf bytes.Buffer
	buf.WriteString(string(d.AuthorID))
	buf.WriteString(d.Timestamp.UTC().Format(time.RFC3339Nano))
	buf.Write(d.ContentCID.Bytes())
	// Add other fields included in the signature if necessary
	return buf.Bytes(), nil
}

// Verify checks the document's signature against the AuthorID.
func (d *Document) Verify() (bool, error) {
	bytesToSign, err := d.BytesToSign()
	if err != nil {
		return false, fmt.Errorf("failed to get bytes for signature verification: %w", err)
	}
	return crypto.VerifySignature(d.AuthorID, bytesToSign, d.Signature)
}

// Helper to encode a node to bytes (e.g., for storage or transmission)
func EncodeNode(node ipld.Node) ([]byte, error) {
	var buf bytes.Buffer
	err := dagjson.Encode(node, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to encode node to DAG-JSON: %w", err)
	}
	return buf.Bytes(), nil
}

// Helper to decode bytes back to a node
func DecodeNode(data []byte) (ipld.Node, error) {
	nb := basicnode.Prototype.Any.NewBuilder()
	err := dagjson.Decode(nb, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode DAG-JSON to node: %w", err)
	}
	return nb.Build(), nil
}
