package transparency

import (
	"crypto/sha256"
	"testing"
)

func buildTestTree(leaves [][]byte) ([32]byte, []InclusionProof) {
	if len(leaves) == 0 {
		return [32]byte{}, nil
	}
	lhashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		lhashes[i] = leafHash(l)
	}
	// Build padded tree.
	cur := make([][32]byte, len(lhashes))
	copy(cur, lhashes)
	levels := [][][32]byte{cur}
	for len(cur) > 1 {
		if len(cur)%2 == 1 {
			cur = append(cur, cur[len(cur)-1])
			levels[len(levels)-1] = append(levels[len(levels)-1], cur[len(cur)-1])
		}
		var next [][32]byte
		for i := 0; i < len(cur); i += 2 {
			next = append(next, parentHash(cur[i], cur[i+1]))
		}
		cur = next
		levels = append(levels, cur)
	}
	root := cur[0]
	// Build proofs.
	var proofs []InclusionProof
	for idx := range leaves {
		var steps []ProofStep
		i := idx
		for level := 0; level < len(levels)-1; level++ {
			sibIdx := i ^ 1
			sibling := levels[level][sibIdx]
			steps = append(steps, ProofStep{
				Sibling:        sibling,
				IsRightSibling: i%2 == 0,
			})
			i >>= 1
		}
		proofs = append(proofs, InclusionProof{Index: uint64(idx), Steps: steps})
	}
	return root, proofs
}

func TestVerifyInclusion(t *testing.T) {
	leaves := [][]byte{
		[]byte("catalog-v1-hash"),
		[]byte("catalog-v2-hash"),
		[]byte("catalog-v3-hash"),
		[]byte("catalog-v4-hash"),
	}
	root, proofs := buildTestTree(leaves)
	for i, leaf := range leaves {
		err := VerifyInclusion(root, leaf, &proofs[i])
		if err != nil {
			t.Fatalf("inclusion proof %d failed: %v", i, err)
		}
	}
}

func TestVerifyInclusionFailsWithWrongData(t *testing.T) {
	leaves := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
	}
	root, proofs := buildTestTree(leaves)
	err := VerifyInclusion(root, []byte("wrong-data"), &proofs[1])
	if err == nil {
		t.Fatal("expected inclusion verification to fail with wrong data")
	}
}

func TestVerifyInclusionFailsWithForgedRoot(t *testing.T) {
	leaves := [][]byte{
		[]byte("x"),
		[]byte("y"),
	}
	root, proofs := buildTestTree(leaves)
	forged := root
	forged[0] ^= 0xff
	err := VerifyInclusion(forged, leaves[0], &proofs[0])
	if err == nil {
		t.Fatal("expected inclusion verification to fail with forged root")
	}
}

func TestVerifyConsistency_SameSize(t *testing.T) {
	h := sha256.Sum256([]byte("root"))
	proof := &ConsistencyProof{
		OldSize: 5,
		NewSize: 5,
		OldRoot: h,
		NewRoot: h,
	}
	err := VerifyConsistency(proof)
	if err != nil {
		t.Fatalf("same-size consistency should verify: %v", err)
	}
}

func TestVerifyConsistency_DetectsRollback(t *testing.T) {
	proof := &ConsistencyProof{
		OldSize: 10,
		NewSize: 5, // smaller!
	}
	err := VerifyConsistency(proof)
	if err == nil {
		t.Fatal("expected rollback detection")
	}
}

func TestVerifyConsistency_EmptyOld(t *testing.T) {
	proof := &ConsistencyProof{
		OldSize: 0,
		NewSize: 5,
	}
	err := VerifyConsistency(proof)
	if err != nil {
		t.Fatalf("empty old tree should be trivially consistent: %v", err)
	}
}

func TestClient_VerifyUpdate(t *testing.T) {
	c := NewClient()
	if c.LastTrustedSTH() != nil {
		t.Fatal("expected nil initial STH")
	}
	sth1 := &SignedTreeHead{TreeSize: 5, Timestamp: 1000}
	c.SetTrustedSTH(sth1)
	if c.LastTrustedSTH().TreeSize != 5 {
		t.Fatal("expected tree size 5")
	}
}
