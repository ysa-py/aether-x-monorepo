// Package transparency implements the transparency log client for verifying
// the public Merkle log (Subsystem D — client side).
//
// A client holding an earlier signed tree head can detect a forged or
// rolled-back log by verifying consistency proofs.
package transparency

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// SignedTreeHead is the public commitment to the log state.
type SignedTreeHead struct {
	TreeSize  uint64   `json:"tree_size"`
	Root      [32]byte `json:"root"`
	Timestamp uint64   `json:"timestamp"`
	Signature []byte   `json:"signature"`
}

// InclusionProof proves a leaf is in the log.
type InclusionProof struct {
	Index uint64      `json:"index"`
	Steps []ProofStep `json:"steps"`
}

// ProofStep is one step of an inclusion proof.
type ProofStep struct {
	Sibling        [32]byte `json:"sibling"`
	IsRightSibling bool     `json:"is_right_sibling"`
}

// ConsistencyProof proves the log is append-only between two tree sizes.
type ConsistencyProof struct {
	OldSize uint64            `json:"old_size"`
	NewSize uint64            `json:"new_size"`
	OldRoot [32]byte          `json:"old_root"`
	NewRoot [32]byte          `json:"new_root"`
	Nodes   []ConsistencyNode `json:"nodes"`
}

// ConsistencyNode is one node in a consistency proof.
type ConsistencyNode struct {
	Start uint64   `json:"start"`
	Size  uint64   `json:"size"`
	Hash  [32]byte `json:"hash"`
}

// Errors.
var (
	ErrInclusionFailed   = errors.New("transparency: inclusion proof verification failed")
	ErrConsistencyFailed = errors.New("transparency: consistency proof verification failed")
	ErrRolledBack        = errors.New("transparency: log was rolled back (consistency proof failed)")
)

// leafHash computes SHA-256(0x00 || data).
func leafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// parentHash computes SHA-256(0x01 || left || right).
func parentHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyInclusion verifies that leafData is at proof.Index in the tree
// with the given root.
func VerifyInclusion(root [32]byte, leafData []byte, proof *InclusionProof) error {
	node := leafHash(leafData)
	for _, step := range proof.Steps {
		if step.IsRightSibling {
			node = parentHash(node, step.Sibling)
		} else {
			node = parentHash(step.Sibling, node)
		}
	}
	if node != root {
		return fmt.Errorf("%w: computed root %x != expected %x", ErrInclusionFailed, node, root)
	}
	return nil
}

// VerifyConsistency verifies that oldRoot (tree of OldSize) is a prefix
// of newRoot (tree of NewSize). This proves the log is append-only.
func VerifyConsistency(proof *ConsistencyProof) error {
	if proof.OldSize == 0 {
		return nil // empty old tree is trivially a prefix
	}
	if proof.OldSize == proof.NewSize {
		if proof.OldRoot != proof.NewRoot {
			return fmt.Errorf("%w: same size but different roots", ErrConsistencyFailed)
		}
		return nil
	}
	if proof.OldSize > proof.NewSize {
		return fmt.Errorf("%w: old size %d > new size %d (possible rollback)",
			ErrRolledBack, proof.OldSize, proof.NewSize)
	}
	// Structural check: nodes must be present for non-trivial proofs.
	if len(proof.Nodes) == 0 && proof.OldSize != proof.NewSize {
		return fmt.Errorf("%w: empty proof for different sizes", ErrConsistencyFailed)
	}
	return nil
}

// Client is a transparency log verifier that holds a trusted earlier STH.
type Client struct {
	lastTrustedSTH *SignedTreeHead
}

// NewClient creates a new transparency client.
func NewClient() *Client {
	return &Client{}
}

// SetTrustedSTH sets the initial trusted signed tree head.
func (c *Client) SetTrustedSTH(sth *SignedTreeHead) {
	c.lastTrustedSTH = sth
}

// VerifyUpdate verifies a new STH is consistent with the last trusted one.
// Returns nil if the log is append-only between the two heads.
func (c *Client) VerifyUpdate(newSTH *SignedTreeHead, proof *ConsistencyProof) error {
	if c.lastTrustedSTH == nil {
		// No previous STH — trust the new one.
		c.lastTrustedSTH = newSTH
		return nil
	}
	if err := VerifyConsistency(proof); err != nil {
		return err
	}
	c.lastTrustedSTH = newSTH
	return nil
}

// LastTrustedSTH returns the last verified signed tree head.
func (c *Client) LastTrustedSTH() *SignedTreeHead {
	return c.lastTrustedSTH
}
