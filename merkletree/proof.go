package merkletree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/filecoin-project/go-data-segment/fr32"
	"log"
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
	Index() int
	// ValidateLeaf ensures the correctness of the proof of a leaf against the root of a Merkle tree
	ValidateLeaf(leafs []byte, root *Node) bool
	// ValidateSubtree ensures the correctness of the proof of a subtree against the root of a Merkle tree
	ValidateSubtree(subtree *Node, root *Node) bool
}

type proofData struct {
	path []Node
	// lvl indicates the level in the Merkle tree where root has level 0
	lvl int
	// idx indicates the index within the level where the element whose membership to prove is located
	// Leftmost node is index 0
	idx int
}

// DeserializeProof deserializes a serialized proof
// This is done by first decoding the index of the node in the proof with the level first and then the index.
// Then the nodes on the verification path are decoded, starting from level 1
// NOTE that correctness of the proof is NOT validated as part of this method
func DeserializeProof(proof []byte) (MerkleProof, error) {
	if proof == nil || len(proof) < 2*BytesInInt {
		log.Println("no proof encoded")
		return proofData{}, errors.New("no proof encoded")
	}
	lvl := int(binary.LittleEndian.Uint64(proof[:BytesInInt]))
	if lvl <= 0 {
		log.Println(fmt.Printf("level must be a positive number:  %d\n", lvl))
		return proofData{}, errors.New("level must be a positive number")
	}
	idx := int(binary.LittleEndian.Uint64(proof[BytesInInt : 2*BytesInInt]))
	if idx < 0 {
		log.Println(fmt.Printf("index cannot be negative: %d\n", lvl))
		return proofData{}, errors.New("index cannot be negative")
	}
	nodes := (len(proof) - 2*BytesInInt) / fr32.BytesNeeded
	if lvl > nodes || (len(proof)-2*BytesInInt)%fr32.BytesNeeded != 0 {
		log.Println(fmt.Printf("proof not properly encoded. Contains %d nodes and validates element at level %d\n", nodes, lvl))
		return proofData{}, errors.New("proof not properly encoded")
	}
	decoded := make([]Node, nodes)
	ctr := 2 * BytesInInt
	for i := 0; i < nodes; i++ {
		nodeBytes := (*[fr32.BytesNeeded]byte)(proof[ctr : ctr+fr32.BytesNeeded])
		decoded[i] = Node{data: *nodeBytes}
		ctr += fr32.BytesNeeded
	}
	return proofData{
		path: decoded,
		lvl:  lvl,
		idx:  idx,
	}, nil
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
		err := binary.Write(buf, binary.LittleEndian, d.Path()[i].data)
		if err != nil {
			log.Println(fmt.Printf("could not write layer %d", i))
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
func (d proofData) Index() int {
	return d.idx
}

// ValidateLeaf validates that the data given as input is contained in a Merkle tree with a specific root
func (d proofData) ValidateLeaf(data []byte, root *Node) bool {
	leaf := truncatedHash(data)
	return d.ValidateSubtree(leaf, root)
}

// ValidateSubtree validates that a subtree is contained in the in a Merkle tree with a given root
func (d proofData) ValidateSubtree(subtree *Node, root *Node) bool {
	currentNode := subtree
	currentIdx := d.idx
	var parent *Node
	for currentLvl := d.lvl; currentLvl >= 1; currentLvl-- {
		sibIdx := getSiblingIdx(currentIdx)
		sibling := d.path[currentLvl-1]
		// If the node is all-0 then it means it does not exist
		// It is fine to assume this "magic" array since all nodes will be hash digests and so the all-0 string
		// will only happen with negligible probability
		if sibling.data == [digestBytes]byte{} {
			// In case the node does not exist, the only child will be hashed
			parent = truncatedHash(currentNode.data[:])
		} else {
			// If the sibling is "right" then we must hash currentNode first
			if sibIdx%2 == 1 {
				parent = computeNode(currentNode, &sibling)
			} else {
				parent = computeNode(&sibling, currentNode)
			}
		}
		currentNode = parent
		currentIdx = currentIdx / 2
	}
	// Validate the root against the tree
	if parent.data != root.data {
		return false
	}
	return true
}
