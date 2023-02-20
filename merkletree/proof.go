package merkletree

import (
	"crypto/sha256"

	"golang.org/x/xerrors"
)

type ProofData struct {
	Path []Node
	// index indicates the index within the level where the element whose membership to prove is located
	// Leftmost node is index 0
	Index uint64
}

// Depth returns the level in the tree which the node this proof validates is located
func (d ProofData) Depth() int {
	return len(d.Path)
}

// ValidateLeaf validates that the data given as input is contained in a Merkle tree with a specific root
func (d ProofData) ValidateLeaf(data []byte, root *Node) error {
	leaf := TruncatedHash(data)
	return d.ValidateSubtree(leaf, root)
}

// ValidateSubtree validates that a subtree is contained in the in a Merkle tree with a given root
func (d ProofData) ValidateSubtree(subtree *Node, root *Node) error {
	// Validate the structure first to avoid panics
	if err := d.validateProofStructure(); err != nil {
		return xerrors.Errorf("in ValidateSubtree: %w", err)
	}
	return d.validateProof(subtree, root)
}

func (d ProofData) ComputeRoot(subtree *Node) (*Node, error) {
	if subtree == nil {
		return nil, xerrors.Errorf("nil subtree cannot be used")
	}
	if d.Depth() > 63 {
		return nil, xerrors.Errorf("merkleproofs with depths greater than 63 are not supported")
	}
	if d.Index>>d.Depth() != 0 {
		return nil, xerrors.Errorf("index greater than width of the tree")
	}

	var carry Node = *subtree
	var index = d.Index
	var right = uint64(0)

	for _, p := range d.Path {
		right, index = index&1, index>>1
		if right == 1 {
			carry = *computeNode(&p, &carry)
		} else {
			carry = *computeNode(&carry, &p)
		}
	}

	return &carry, nil
}

// computeNode computes a new internal node in a tree, from its left and right children
func computeNode(left *Node, right *Node) *Node {
	sha := sha256.New()
	sha.Write(left[:])
	sha.Write(right[:])
	digest := sha.Sum(nil)

	return truncate((*Node)(digest))
}

func truncate(n *Node) *Node {
	n[256/8-1] &= 0b00111111
	return n
}

func (d ProofData) validateProof(subtree *Node, root *Node) error {
	computedRoot, err := d.ComputeRoot(subtree)
	if err != nil {
		return xerrors.Errorf("computing root: %w", err)
	}

	if *computedRoot != *root {
		return xerrors.Errorf("inclusion proof does not lead to the same root")
	}
	return nil
}

func (d ProofData) validateProofStructure() error {
	return nil
}
