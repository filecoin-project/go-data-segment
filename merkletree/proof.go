package merkletree

import (
	"bytes"
	"encoding/binary"

	"github.com/filecoin-project/go-data-segment/fr32"
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
}

type proofData struct {
	path []Node
	// index indicates the index within the level where the element whose membership to prove is located
	// Leftmost node is index 0
	index uint64
}

// DeserializeProof deserializes a serialized proof
// This is done by first decoding the index of the node in the proof with the level first and then the index.
// Then the nodes on the verification path are decoded, starting from level 1
// NOTE that correctness, nor the structure of the proof is NOT validated as part of this method
func DeserializeProof(proof []byte) (MerkleProof, error) {
	if proof == nil {
		return nil, xerrors.New("no proof encoded")
	}
	nodes := (len(proof) - BytesInInt) / fr32.BytesNeeded
	if (len(proof)-BytesInInt)%fr32.BytesNeeded != 0 {
		return nil, xerrors.New("proof not properly encoded")
	}
	idx := binary.LittleEndian.Uint64(proof[:BytesInInt])
	decoded := make([]Node, nodes)
	proof = proof[BytesInInt:]
	for i := 0; i < nodes; i++ {
		decoded[i] = *(*Node)(proof[:fr32.BytesNeeded])
		proof = proof[fr32.BytesNeeded:]
	}
	res := proofData{
		path:  decoded,
		index: idx,
	}
	if err := res.validateProofStructure(); err != nil {
		return nil, xerrors.Errorf("the data does not contain a valid proof: %w", err)
	}
	return res, nil
}

// Serialize serializes the proof into a byte slice
// This is done by first encoding the index of the node in the proof with the level first and then the index.
// Then the nodes on the verification path are encoded, starting from level 1
// NOTE that correctness of the proof is NOT validated as part of this method
func (d proofData) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, d.index)
	if err != nil {
		return nil, xerrors.Errorf("writing leaf count: %w", err)
	}

	for _, p := range d.path {
		err := binary.Write(buf, binary.LittleEndian, p[:])
		if err != nil {
			return nil, xerrors.Errorf("writing path data: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// Path returns the nodes in the path of the proof.
// The first node, is in level 1. I.e. the level below the root
func (d proofData) Path() []Node {
	return d.path
}

// Depth returns the level in the tree which the node this proof validates is located
func (d proofData) Depth() int {
	return len(d.path)
}

// Index returns the index of the node this proof validates, within the level returned by Level()
func (d proofData) Index() uint64 {
	return d.index
}

// ValidateLeaf validates that the data given as input is contained in a Merkle tree with a specific root
func (d proofData) ValidateLeaf(data []byte, root *Node) error {
	leaf := TruncatedHash(data)
	return d.ValidateSubtree(leaf, root)
}

// ValidateSubtree validates that a subtree is contained in the in a Merkle tree with a given root
func (d proofData) ValidateSubtree(subtree *Node, root *Node) error {
	// Validate the structure first to avoid panics
	if err := d.validateProofStructure(); err != nil {
		return xerrors.Errorf("in ValidateSubtree: %w", err)
	}
	return d.validateProof(subtree, root)
}

func (d proofData) computeRoot(subtree *Node) (*Node, error) {
	if subtree == nil {
		return nil, xerrors.Errorf("nil subtree cannot be used")
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

func (d proofData) validateProof(subtree *Node, root *Node) error {
	computedRoot, err := d.computeRoot(subtree)
	if err != nil {
		return xerrors.Errorf("computing root: %w", err)
	}

	if *computedRoot != *root {
		return xerrors.Errorf("inclusion proof does not lead to the same root")
	}
	return nil
}

func (d proofData) validateProofStructure() error {
	return nil
}
