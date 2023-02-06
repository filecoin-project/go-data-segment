package merkletree

import (
	"bytes"
	"encoding/binary"
	"log"
	"math"

	"github.com/filecoin-project/go-data-segment/fr32"
	"golang.org/x/xerrors"
)

// MerkleProof represents a Merkle proof to a single leaf in a Merkle tree
type MerkleProof interface {
	// Serialize serializes the proof into a byte slice
	Serialize() ([]byte, error)
	// Path returns the nodes in the proof, starting level 1 (the children of the root)
	Path() []Node
	// Level returns the level in the tree of the node in the tree which the proof validates.
	// The root node is at level 0.
	Level() int
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
	// lvl indicates the level in the Merkle tree where root has level 0
	lvl int
	// idx indicates the index within the level where the element whose membership to prove is located
	// Leftmost node is index 0
	idx uint64
}

// DeserializeProof deserializes a serialized proof
// This is done by first decoding the index of the node in the proof with the level first and then the index.
// Then the nodes on the verification path are decoded, starting from level 1
// NOTE that correctness, nor the structure of the proof is NOT validated as part of this method
func DeserializeProof(proof []byte) (MerkleProof, error) {
	if proof == nil {
		return nil, xerrors.New("no proof encoded")
	}
	nodes := (len(proof) - 2*BytesInInt) / fr32.BytesNeeded
	if (len(proof)-2*BytesInInt)%fr32.BytesNeeded != 0 {
		return nil, xerrors.New("proof not properly encoded")
	}
	lvl := binary.LittleEndian.Uint64(proof[:BytesInInt])
	if lvl > math.MaxInt32 {
		return nil, xerrors.Errorf("lvl greater than max value")
	}

	idx := binary.LittleEndian.Uint64(proof[BytesInInt : 2*BytesInInt])
	decoded := make([]Node, nodes)
	ctr := 2 * BytesInInt
	for i := 0; i < nodes; i++ {
		nodeBytes := (*[fr32.BytesNeeded]byte)(proof[ctr : ctr+fr32.BytesNeeded])
		decoded[i] = Node{Data: *nodeBytes}
		ctr += fr32.BytesNeeded
	}
	res := proofData{
		path: decoded,
		lvl:  int(lvl),
		idx:  idx,
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
	// TODO can we make any general size assumptions to avoid 128 bits for encoding the index
	// Encode level and index as 64 bit unsigned ints
	err := binary.Write(buf, binary.LittleEndian, uint64(d.Level()))
	if err != nil {
		log.Println("could not write the leaf count")
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(d.Index()))
	if err != nil {
		log.Println("could not write the leaf count")
		return nil, err
	}
	for i := 0; i < len(d.Path()); i++ {
		err := binary.Write(buf, binary.LittleEndian, d.Path()[i].Data)
		if err != nil {
			log.Printf("could not write layer %d\n", i)
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// Path returns the nodes in the path of the proof.
// The first node, is in level 1. I.e. the level below the root
func (d proofData) Path() []Node {
	return d.path
}

// Level returns the level in the tree which the node this proof validates, is located
func (d proofData) Level() int {
	return d.lvl
}

// Index returns the index of the node this proof validates, within the level returned by Level()
func (d proofData) Index() uint64 {
	return d.idx
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

func (d proofData) validateProof(subtree *Node, root *Node) error {
	currentNode := subtree
	currentIdx := d.idx
	var parent *Node
	for currentLvl := d.lvl; currentLvl >= 1; currentLvl-- {
		sibIdx := getSiblingIdx(currentIdx)
		sibling := d.path[currentLvl-1]
		// If the sibling is "right" then we must hash currentNode first
		if sibIdx%2 == 1 {
			parent = computeNode(currentNode, &sibling)
		} else {
			parent = computeNode(&sibling, currentNode)
		}
		currentNode = parent
		currentIdx = currentIdx / 2
	}
	// Validate the root against the tree
	if parent.Data != root.Data {
		return xerrors.Errorf("inclusion proof does not lead to the same root")
	}
	return nil
}

func (d proofData) validateProofStructure() error {
	if d.Level() <= 0 {
		return xerrors.Errorf("level must be positive: %d <= 0", d.Level())
	}
	if d.Level() > len(d.Path()) {
		return xerrors.Errorf("level %d is greater than the length of the path in the proof: %d\n", d.Level(), len(d.Path()))
	}
	return nil
}
