package merkletree

import (
	"bytes"

	"golang.org/x/xerrors"
)

// MerkleProof represents a Merkle proof to a single leaf in a Merkle tree
type MerkleProof interface {
	// Serialize serializes the proof into a byte slice
	Serialize() ([]byte, error)
	// Path returns the nodes in the proof, starting level 1 (the children of the root)
	Path() []Node
	// Depth returns how far into the tree given MerkleProof reaches
	Depth() int
	// Index returns the index of the node which the proof validates
	// The left-most node in a given level is 0
	Index() uint64
	// ValidateLeaf ensures the correctness of the proof of a leaf against the root of a Merkle tree
	ValidateLeaf(leafs []byte, root *Node) error
	// ValidateSubtree ensures the correctness of the proof of a subtree against the root of a Merkle tree
	ValidateSubtree(subtree *Node, root *Node) error
	// ComputeRoot computes the root of a tree given given node at the end of the path.
	ComputeRoot(subtree *Node) (*Node, error)
}

type ProofData struct {
	path []Node
	// index indicates the index within the level where the element whose membership to prove is located
	// Leftmost node is index 0
	index uint64
}

// DeserializeProof deserializes a serialized proof
// NOTE that correctness, nor the structure of the proof is NOT validated as part of this method
func DeserializeProof(proof []byte) (ProofData, error) {
	var res ProofData

	if err := res.UnmarshalCBOR(bytes.NewReader(proof)); err != nil {
		return ProofData{}, xerrors.Errorf("decoding proof")
	}

	if err := res.validateProofStructure(); err != nil {
		return ProofData{}, xerrors.Errorf("the data does not contain a valid proof: %w", err)
	}
	return res, nil
}

// Serialize serializes the proof into a byte slice
// NOTE that correctness of the proof is NOT validated as part of this method
func (d ProofData) Serialize() ([]byte, error) {
	wb := new(bytes.Buffer)
	d.MarshalCBOR(wb)
	return wb.Bytes(), nil
}

// Path returns the nodes in the path of the proof.
// The first node, is in level 1. I.e. the level below the root
func (d ProofData) Path() []Node {
	return d.path
}

// Depth returns the level in the tree which the node this proof validates is located
func (d ProofData) Depth() int {
	return len(d.path)
}

// Index returns the index of the node this proof validates, within the level returned by Level()
func (d ProofData) Index() uint64 {
	return d.index
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
	if d.Depth() > 64 {
		return nil, xerrors.Errorf("merkleproofs with depths greater than 64 are not supported")
	}
	if d.index>>d.Depth() != 0 {
		return nil, xerrors.Errorf("index greater than width of the tree")
	}

	var carry Node = *subtree
	var index = d.index
	var right = uint64(0)

	for i := len(d.path) - 1; i >= 0; i-- {
		right, index = index&1, index>>1
		if right == 1 {
			carry = *computeNode(&d.path[i], &carry)
		} else {
			carry = *computeNode(&carry, &d.path[i])
		}
	}

	return &carry, nil
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
