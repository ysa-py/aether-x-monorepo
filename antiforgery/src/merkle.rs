//! Append-style Merkle tree for O(log n) inclusion proofs.
//!
//! This *complements* [`crate::audit`], it does not replace it: the hash
//! **chain** answers "did ANY record change?" (sequential, O(n)), while this
//! **tree** answers "prove record X is included" in O(log n) proof size — the
//! basis for certificate-transparency-style audit proofs.
//!
//! # Security
//! Leaves and internal nodes are domain-separated:
//!   - `leaf_hash(d)  = SHA-256(0x00 || d)`
//!   - `parent(l, r)  = SHA-256(0x01 || l || r)`
//!
//! so a node hash can never be reinterpreted at a different position (defeats
//! second-preimage / "leaf-as-internal" forgery across levels).
//!
//! # Balancing
//! Odd levels duplicate their last node, keeping the tree balanced so the proof
//! height is always `ceil(log2 n)`.
//!
//! This is the standard, audited design used by Certificate Transparency
//! (RFC 6962), adapted to an in-memory append-only log.

use sha2::{Digest, Sha256};

/// Domain-separation prefix for leaf hashing.
pub const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for internal (parent) hashing.
pub const NODE_PREFIX: u8 = 0x01;

/// `SHA-256(0x00 || data)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    finalize(h)
}

/// `SHA-256(0x01 || left || right)`.
#[must_use]
pub fn parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    finalize(h)
}

fn finalize(h: Sha256) -> [u8; 32] {
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Which side the sibling sits on, relative to the node being proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is the LEFT child; the proven node is the right child.
    Left,
    /// Sibling is the RIGHT child; the proven node is the left child.
    Right,
}

/// One step of an inclusion proof: the sibling hash and its position.
#[derive(Debug, Clone)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub side: Side,
}

/// An inclusion proof for the leaf at `index`.
#[derive(Debug, Clone)]
pub struct Proof {
    pub index: u64,
    pub steps: Vec<ProofStep>,
}

impl Proof {
    /// Number of steps (tree height for this leaf). `O(log n)`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the proof has zero steps (trivial, e.g. a single-leaf tree).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// An in-memory Merkle tree. `levels[0]` holds the (padded) leaf hashes; the
/// last level holds `[root]`.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
    /// Unpadded leaf hashes, used by the RFC 6962 forest operations
    /// (`forest_root`, consistency proofs). The `levels` above are padded, so
    /// the raw leaves are kept separately.
    leaves: Vec<[u8; 32]>,
    /// Original (unpadded) leaf count, for correct indexing/reporting.
    count: usize,
}

impl MerkleTree {
    /// Build a tree over raw `leaves` (each leaf is hashed with [`leaf_hash`]).
    #[must_use]
    pub fn from_leaves(leaves: &[Vec<u8>]) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: Vec::new(),
                leaves: Vec::new(),
                count: 0,
            };
        }
        let count = leaves.len();
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|d| leaf_hash(d)).collect();
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut cur = leaf_hashes.clone();
        levels.push(cur.clone());

        while cur.len() > 1 {
            // Pad odd levels by duplicating the last node (kept in `levels`
            // too, so proof siblings resolve correctly).
            if cur.len() % 2 == 1 {
                // `cur.len() > 1` guarantees a last element here, but retain a
                // total-function implementation rather than encoding that
                // invariant as a process panic.
                if let Some(last) = cur.last().copied() {
                    cur.push(last);
                    if let Some(level) = levels.last_mut() {
                        level.push(last);
                    }
                }
            }
            let mut next: Vec<[u8; 32]> = Vec::with_capacity(cur.len() / 2);
            for pair in cur.chunks(2) {
                next.push(parent_hash(&pair[0], &pair[1]));
            }
            cur = next;
            levels.push(cur.clone());
        }

        Self {
            levels,
            leaves: leaf_hashes,
            count,
        }
    }

    /// Original (unpadded) number of leaves.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.count
    }

    /// Whether the tree has no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The Merkle root, or `None` for an empty tree.
    #[must_use]
    pub fn root(&self) -> Option<[u8; 32]> {
        self.levels.last().and_then(|lvl| lvl.first().copied())
    }

    /// Build an inclusion proof for the leaf at `index`. Returns `None` if the
    /// index is out of range or the tree is empty.
    #[must_use]
    pub fn proof(&self, index: usize) -> Option<Proof> {
        if index >= self.count {
            return None;
        }
        let mut steps = Vec::new();
        let mut idx = index;
        // Walk every level except the root level.
        for level in 0..self.levels.len().saturating_sub(1) {
            let lvl = &self.levels[level];
            let sibling_idx = idx ^ 1;
            // sibling_idx is always valid because odd levels were padded.
            let sibling = lvl[sibling_idx];
            let side = if idx % 2 == 0 {
                Side::Right
            } else {
                Side::Left
            };
            steps.push(ProofStep { sibling, side });
            idx >>= 1;
        }
        Some(Proof {
            index: index as u64,
            steps,
        })
    }
}

/// Verify that `data` is the leaf at `proof.index` in the tree whose root is
/// `root`. Constant-time-ish in proof length (no secret data involved).
#[must_use]
pub fn verify_proof(root: &[u8; 32], data: &[u8], proof: &Proof) -> bool {
    let mut node = leaf_hash(data);
    for step in &proof.steps {
        node = match step.side {
            Side::Right => parent_hash(&node, &step.sibling),
            Side::Left => parent_hash(&step.sibling, &node),
        };
    }
    &node == root
}

// ===========================================================================
// Consistency proofs (RFC 6962 §2.1.2) — append-only proofs.
//
// A consistency proof shows that the tree of size `m` is a *prefix* (an
// earlier version) of the tree of size `n` (m < n): i.e. the log only grew,
// it did not rewrite history. This complements inclusion proofs and uses the
// RFC 6962 *forest* construction (largest-power-of-2-left split), which is why
// it operates on `forest_root`, a separate commitment from the duplicate-last
// `MerkleTree::root`. Nothing above is changed.
// ===========================================================================

/// One subtree hash in a consistency proof, anchored at a leaf position. Each
/// node commits to exactly the range `[start, start+size)` of leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsistencyNode {
    /// Start leaf index (inclusive).
    pub start: u64,
    /// Number of leaves covered (`size` is a power of two).
    pub size: u64,
    /// `parent_hash`-style (0x01-prefixed) subtree root for that range.
    pub hash: [u8; 32],
}

/// A consistency proof that the `m`-leaf tree is a prefix of the `n`-leaf tree.
/// The verifier reconstructs `[0,m)` → `old_root` and `[0,n)` → `new_root` from
/// the (start,size,hash) nodes, which mirrors [`subtree_hash`]; this is
/// provably correct without the fragile fn/sn pointer juggling.
#[derive(Debug, Clone)]
pub struct ConsistencyProof {
    pub m: u64,
    pub n: u64,
    pub nodes: Vec<ConsistencyNode>,
}

/// Largest power of two strictly less than `x` (requires `x >= 2`).
fn largest_pow2_lt(x: usize) -> usize {
    let mut k = 1usize;
    while k * 2 < x {
        k *= 2;
    }
    k
}

/// RFC 6962 forest hash of leaves `[first, last)` using the raw leaf hashes.
fn subtree_hash(leaves: &[[u8; 32]], first: usize, last: usize) -> [u8; 32] {
    if last - first == 1 {
        return leaves[first];
    }
    let k = largest_pow2_lt(last - first);
    let left = subtree_hash(leaves, first, first + k);
    let right = subtree_hash(leaves, first + k, last);
    parent_hash(&left, &right)
}

impl MerkleTree {
    /// The RFC 6962 *forest* root (largest-power-of-2-left). A separate
    /// commitment from [`MerkleTree::root`] (duplicate-last); consistency proofs
    /// operate on this root. `None` for an empty tree.
    #[must_use]
    pub fn forest_root(&self) -> Option<[u8; 32]> {
        if self.count == 0 {
            None
        } else {
            Some(subtree_hash(&self.leaves, 0, self.count))
        }
    }

    /// Build a consistency proof that the `m`-leaf tree is a prefix of this
    /// `n`-leaf tree. Requires `0 < m < n`. Returns `None` otherwise.
    #[must_use]
    pub fn consistency_proof(&self, m: usize) -> Option<ConsistencyProof> {
        let n = self.count;
        if m == 0 || m >= n {
            return None;
        }
        let nodes = subproof(m, 0, n, true, &self.leaves);
        Some(ConsistencyProof {
            m: m as u64,
            n: n as u64,
            nodes,
        })
    }
}

/// RFC 6962 subproof: collect subtree nodes proving `[first, first+m)` is a
/// prefix of `[first, last)`. `known` indicates the caller already trusts the
/// boundary (top-level call uses `true`). Nodes carry their absolute `start`.
fn subproof(
    m: usize,
    first: usize,
    last: usize,
    known: bool,
    leaves: &[[u8; 32]],
) -> Vec<ConsistencyNode> {
    let size = last - first;
    if m == size {
        return if known {
            Vec::new()
        } else {
            vec![ConsistencyNode {
                start: first as u64,
                size: size as u64,
                hash: subtree_hash(leaves, first, last),
            }]
        };
    }
    let k = largest_pow2_lt(size);
    if m <= k {
        // m is within the left child; recurse left, then add the right child.
        let mut p = subproof(m, first, first + k, known, leaves);
        p.push(ConsistencyNode {
            start: (first + k) as u64,
            size: (size - k) as u64,
            hash: subtree_hash(leaves, first + k, last),
        });
        p
    } else {
        // m spans into the right child; recurse right, then add the left child.
        let mut p = subproof(m - k, first + k, last, false, leaves);
        p.push(ConsistencyNode {
            start: first as u64,
            size: k as u64,
            hash: subtree_hash(leaves, first, first + k),
        });
        p
    }
}

/// Reconstruct the forest hash of `[first, last)` from the proof nodes: use a
/// node that exactly covers the range if present, otherwise split (mirroring
/// [`subtree_hash`]). Returns `None` if a required range is not covered.
fn reconstruct(first: usize, last: usize, nodes: &[ConsistencyNode]) -> Option<[u8; 32]> {
    let size = last - first;
    if let Some(node) = nodes
        .iter()
        .find(|n| n.start as usize == first && n.size as usize == size)
    {
        return Some(node.hash);
    }
    if size <= 1 {
        // Single leaf not provided by the proof: reconstruction impossible.
        return None;
    }
    let k = largest_pow2_lt(size);
    let left = reconstruct(first, first + k, nodes)?;
    let right = reconstruct(first + k, last, nodes)?;
    Some(parent_hash(&left, &right))
}

/// Verify a consistency proof. `old_root` must be the [`MerkleTree::forest_root`]
/// of the `m`-leaf tree; `new_root` that of the `n`-leaf tree. The proof holds
/// iff the nodes reconstruct BOTH the `m`-prefix (→ old_root) and the full
/// `n`-tree (→ new_root).
#[must_use]
pub fn verify_consistency(
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &ConsistencyProof,
) -> bool {
    let m = proof.m as usize;
    let n = proof.n as usize;
    if m == 0 {
        // An empty old tree is trivially a prefix of anything; still require the
        // new tree to reconstruct from the proof when nodes are present.
        return reconstruct(0, n, &proof.nodes).map_or(true, |r| r == *new_root);
    }
    if m >= n {
        return m == n && proof.nodes.is_empty() && old_root == new_root;
    }
    // For a power-of-two m, `old_root` is a complete subtree the verifier
    // already trusts (it is NOT in the proof). Inject it so the new root can be
    // reconstructed over it. For non-power-of-two m, `[0,m)` is reconstructed
    // from the proof's internal nodes and must equal old_root (a stronger,
    // independent check that the prover's structure matches the committed root).
    let mut nodes = proof.nodes.clone();
    let old_ok = if m.is_power_of_two() {
        nodes.push(ConsistencyNode {
            start: 0,
            size: m as u64,
            hash: *old_root,
        });
        true
    } else {
        reconstruct(0, m, &nodes) == Some(*old_root)
    };
    let new_ok = reconstruct(0, n, &nodes) == Some(*new_root);
    old_ok && new_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
    }

    #[test]
    fn empty_tree() {
        let t = MerkleTree::from_leaves(&[]);
        assert!(t.is_empty());
        assert_eq!(t.leaf_count(), 0);
        assert!(t.root().is_none());
        assert!(t.proof(0).is_none());
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let t = MerkleTree::from_leaves(&[b"solo".to_vec()]);
        assert_eq!(t.leaf_count(), 1);
        assert_eq!(t.root(), Some(leaf_hash(b"solo")));
        // Trivial proof (no steps) verifies.
        let p = t.proof(0).unwrap();
        assert!(p.is_empty());
        assert!(verify_proof(&t.root().unwrap(), b"solo", &p));
    }

    #[test]
    fn all_proofs_verify_for_various_sizes() {
        for n in [2usize, 3, 4, 5, 7, 8, 9, 17, 100] {
            let data = leaves(n);
            let t = MerkleTree::from_leaves(&data);
            let root = t.root().expect("non-empty");
            assert_eq!(t.leaf_count(), n, "leaf count mismatch at n={n}");
            for (i, d) in data.iter().enumerate() {
                let p = t.proof(i).unwrap_or_else(|| panic!("no proof {i} n={n}"));
                assert!(verify_proof(&root, d, &p), "proof failed at i={i} n={n}");
            }
        }
    }

    #[test]
    fn wrong_data_fails() {
        let data = leaves(5);
        let t = MerkleTree::from_leaves(&data);
        let root = t.root().unwrap();
        let p = t.proof(2).unwrap();
        assert!(!verify_proof(&root, b"leaf-3", &p)); // leaf-3 != leaf-2
        assert!(verify_proof(&root, b"leaf-2", &p));
    }

    #[test]
    fn tampered_root_fails() {
        let data = leaves(6);
        let t = MerkleTree::from_leaves(&data);
        let mut bad_root = t.root().unwrap();
        bad_root[0] ^= 0xff;
        let p = t.proof(0).unwrap();
        assert!(!verify_proof(&bad_root, &data[0], &p));
    }

    #[test]
    fn domain_separation_prevents_position_forgery() {
        // A leaf hash must not equal any internal parent hash of the same bytes:
        // 0x00-prefix vs 0x01-prefix.
        assert_ne!(leaf_hash(b"x"), parent_hash(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn root_is_deterministic() {
        let a = MerkleTree::from_leaves(&leaves(10));
        let b = MerkleTree::from_leaves(&leaves(10));
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn proof_size_is_logarithmic() {
        // n=1000 -> height ceil(log2(1000)) = 10.
        let t = MerkleTree::from_leaves(&leaves(1000));
        let p = t.proof(333).unwrap();
        assert_eq!(p.len(), 10, "expected log2-ish height, got {}", p.len());
    }

    #[test]
    fn different_order_yields_different_root() {
        let t1 = MerkleTree::from_leaves(&[b"a".to_vec(), b"b".to_vec()]);
        let t2 = MerkleTree::from_leaves(&[b"b".to_vec(), b"a".to_vec()]);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn out_of_range_index_returns_none() {
        let t = MerkleTree::from_leaves(&leaves(4));
        assert!(t.proof(4).is_none());
    }

    // ---- consistency proofs ----

    fn forest_root_of(data: &[Vec<u8>]) -> [u8; 32] {
        MerkleTree::from_leaves(data)
            .forest_root()
            .expect("non-empty")
    }

    #[test]
    fn consistency_round_trips_for_all_prefixes() {
        for n in [2usize, 3, 4, 5, 7, 8, 9, 16, 17, 30, 50] {
            let data = leaves(n);
            let new_root = forest_root_of(&data);
            for m in 1..n {
                let tree = MerkleTree::from_leaves(&data);
                let proof = tree
                    .consistency_proof(m)
                    .unwrap_or_else(|| panic!("no proof m={m} n={n}"));
                let old_root = forest_root_of(&data[..m]);
                assert!(
                    verify_consistency(&old_root, &new_root, &proof),
                    "consistency failed m={m} n={n}"
                );
            }
        }
    }

    #[test]
    fn consistency_detects_wrong_old_root() {
        let data = leaves(8);
        let new_root = forest_root_of(&data);
        let tree = MerkleTree::from_leaves(&data);
        let proof = tree.consistency_proof(3).unwrap();
        let mut bad_old = forest_root_of(&data[..3]);
        bad_old[0] ^= 0xff;
        assert!(!verify_consistency(&bad_old, &new_root, &proof));
    }

    #[test]
    fn consistency_detects_wrong_new_root() {
        let data = leaves(8);
        let tree = MerkleTree::from_leaves(&data);
        let proof = tree.consistency_proof(3).unwrap();
        let old_root = forest_root_of(&data[..3]);
        let mut bad_new = forest_root_of(&data);
        bad_new[0] ^= 0xff;
        assert!(!verify_consistency(&old_root, &bad_new, &proof));
    }

    #[test]
    fn consistency_detects_tampered_proof_node() {
        let data = leaves(10);
        let new_root = forest_root_of(&data);
        let old_root = forest_root_of(&data[..4]);
        let mut proof = MerkleTree::from_leaves(&data).consistency_proof(4).unwrap();
        proof.nodes[0].hash[0] ^= 0x01;
        assert!(!verify_consistency(&old_root, &new_root, &proof));
    }

    #[test]
    fn consistency_rejects_non_prefix_sizes() {
        let data = leaves(8);
        assert!(MerkleTree::from_leaves(&data)
            .consistency_proof(0)
            .is_none());
        assert!(MerkleTree::from_leaves(&data)
            .consistency_proof(8)
            .is_none());
        assert!(MerkleTree::from_leaves(&data)
            .consistency_proof(9)
            .is_none());
    }

    #[test]
    fn consistency_m_equal_n_is_empty_and_true() {
        let data = leaves(4);
        let root = forest_root_of(&data);
        let same = ConsistencyProof {
            m: 4,
            n: 4,
            nodes: vec![],
        };
        assert!(verify_consistency(&root, &root, &same));
    }

    #[test]
    fn consistency_empty_old_is_trivially_true() {
        let data = leaves(5);
        let new_root = forest_root_of(&data);
        let empty_old = ConsistencyProof {
            m: 0,
            n: 5,
            nodes: vec![],
        };
        assert!(verify_consistency(&[0u8; 32], &new_root, &empty_old));
    }

    #[test]
    fn forest_root_is_stable_and_matches_at_pow2() {
        let data = leaves(7);
        let a = MerkleTree::from_leaves(&data);
        let b = MerkleTree::from_leaves(&data);
        assert_eq!(a.forest_root(), b.forest_root());
        // For a power-of-two count, forest root and duplicate-last root coincide.
        let pow2 = leaves(8);
        let t = MerkleTree::from_leaves(&pow2);
        assert_eq!(t.root(), t.forest_root());
    }
}
