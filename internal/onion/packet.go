// filepath: /home/jony/Project/decentralize-wikileaks/internal/onion/packet.go
package onion

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
)

// HopInfo contains routing information for the next hop.
type HopInfo struct {
	NextPeer peer.ID
	// Potentially add HMAC or other integrity checks here
}

// OnionPacket represents one layer of the onion.
// It contains routing info for the next hop and the encrypted payload.
type OnionPacket struct {
	CircuitID        string // Identifies which circuit this packet belongs to on the relay
	HopInfo          HopInfo
	EncryptedPayload []byte // Encrypted data (either another OnionPacket or InnerPayload)
}

// InnerPayload represents the final message destined for the recipient.
type InnerPayload struct {
	FinalRecipient peer.ID // The ultimate destination PeerID
	MessageType    uint    // Define message types (e.g., PublishDocument, RequestBlock, etc.)
	Data           []byte  // The actual application data (e.g., marshalled core.Document, block data)
	// Optional: Reply Path information (e.g., SURB)
}

// --- Serialization Helpers ---

func EncodeHopInfo(hi *HopInfo) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(hi); err != nil {
		return nil, fmt.Errorf("failed to encode HopInfo: %w", err)
	}
	return buf.Bytes(), nil
}

func DecodeHopInfo(data []byte) (*HopInfo, error) {
	var hi HopInfo
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&hi); err != nil {
		return nil, fmt.Errorf("failed to decode HopInfo: %w", err)
	}
	return &hi, nil
}

func EncodeOnionPacket(op *OnionPacket) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(op); err != nil {
		return nil, fmt.Errorf("failed to encode OnionPacket: %w", err)
	}
	return buf.Bytes(), nil
}

func DecodeOnionPacket(data []byte) (*OnionPacket, error) {
	var op OnionPacket
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&op); err != nil {
		return nil, fmt.Errorf("failed to decode OnionPacket: %w", err)
	}
	return &op, nil
}

func EncodeInnerPayload(ip *InnerPayload) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(ip); err != nil {
		return nil, fmt.Errorf("failed to encode InnerPayload: %w", err)
	}
	return buf.Bytes(), nil
}

func DecodeInnerPayload(data []byte) (*InnerPayload, error) {
	var ip InnerPayload
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&ip); err != nil {
		return nil, fmt.Errorf("failed to decode InnerPayload: %w", err)
	}
	return &ip, nil
}
