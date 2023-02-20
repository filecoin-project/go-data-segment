package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"reflect"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/util"
	"golang.org/x/xerrors"
)

const NodeSize = 32

// BytesInInt represents the amount of bytes used to encode an int
const BytesInInt int = 64 / 8

// MerkleTree represents a Merkle tree which can be used to construct proof of containment for either leafs, subtrees or a sequence of leafs (subtrees)
type MerkleTree interface {
	// Depth returns the Depth of the tree. A single-node tree has Depth 1
	Depth() int
	// LeafCount returns the amount of leafs in the Merkle tree
	LeafCount() uint64
	// Root returns the root node of the tree
	Root() *Node
	// Leafs returns all the leaf nodes in the tree
	Leafs() []Node
	// Node returns the node at given lvl and idx
	Node(int, uint64) *Node
	// ConstructProof constructs a Merkle proof of the subtree (or leaf) at level lvl with index idx.
	// level 0 is the root and index 0 is the left-most node in a level.
	ConstructProof(lvl int, idx uint64) (*ProofData, error)
	// ValidateFromLeafs checks that the Merkle tree is correctly constructed based on all the leafData
	ValidateFromLeafs(leafData [][]byte) error
	// Validate checks that the Merkle tree is correctly constructed, based on the internal nodes
	Validate() bool
	// Serialize serializes the MerkleTree into a byte slice
	Serialize() ([]byte, error)
}

type TreeData struct {
	// nodes start from root and go down left-to-right
	// thus len(nodes[0]) = 1, len(nodes[1]) = 2, etc.
	nodes [][]Node
	// leafs is the amount of raw leafs being used. I.e. without padding to nearest two-power
	leafs uint64
}

var _ MerkleTree = TreeData{}

type Node [NodeSize]byte

func (n *Node) IsZero() bool {
	return *n == (Node{})
}

// newBareTree allocates that memory needed to construct a tree with a specific amount of leafs.
// The construction rounds the amount of leafs up to the nearest two-power with zeroed nodes to ensure
// that the tree is perfect and hence all internal node's have well-defined children.
func newBareTree(leafs uint64) *TreeData {
	adjustedLeafs := 1 << util.Log2Ceil(uint64(leafs))
	var tree TreeData
	tree.nodes = make([][]Node, 1+util.Log2Ceil(uint64(adjustedLeafs)))
	tree.leafs = leafs
	for i := 0; i <= util.Log2Ceil(uint64(adjustedLeafs)); i++ {
		tree.nodes[i] = make([]Node, 1<<i)
	}
	return &tree
}

// DeserializeTree deserializes a serialized Merkle tree
// This is done by first reading the amount of leafs as a 64 bit int
// Then decoding the tree, bottom-up, starting with the leafs as the amount of nodes in one level defines the amount of nodes in its parent level
// NOTE that correctness of the tree is NOT validated as part of this method
func DeserializeTree(tree []byte) (*TreeData, error) {
	if tree == nil || len(tree) < BytesInInt {
		return nil, xerrors.New("no tree encoded")
	}
	lvlSize := binary.LittleEndian.Uint64(tree[:BytesInInt])
	decoded := newBareTree(lvlSize)
	lvlSize = 1 << util.Log2Ceil(lvlSize)
	ctr := BytesInInt
	// Decode from the leafs
	for i := decoded.Depth() - 1; i >= 0; i-- {
		if len(tree) < ctr+fr32.BytesNeeded*int(lvlSize) {
			return nil, xerrors.Errorf("error in tree encoding, does not contain level %d", i)
		}
		currentLvl := make([]Node, lvlSize)
		for j := uint64(0); j < lvlSize; j++ {
			currentLvl[j] = *(*Node)(tree[ctr : ctr+fr32.BytesNeeded])
			ctr += fr32.BytesNeeded
		}
		decoded.nodes[i] = currentLvl
		// The amount of nodes in the parent level is half, rounded up
		lvlSize = lvlSize >> 1
	}
	return decoded, nil
}

// GrowTree constructs a Merkle from a list of leafData, the data of a given leaf is represented as a byte slice
// The construction rounds the amount of leafs up to the nearest two-power with zeroed nodes to ensure
// that the tree is perfect and hence all internal node's have well-defined children.
// TODO should things be hard-coded to work on 32 byte leafs?
func GrowTree(leafData [][]byte) (*TreeData, error) {
	if len(leafData) == 0 {
		return nil, errors.New("empty input")
	}
	leafLevel := hashList(leafData)
	return GrowTreeHashedLeafs(leafLevel), nil
}

// GrowTreeHashedLeafs constructs a tree from leafs nodes, i.e. leaf data that has been hashed to construct a Node
func GrowTreeHashedLeafs(leafs []Node) *TreeData {
	tree := newBareTree(uint64(len(leafs)))
	tree.leafs = uint64(len(leafs))
	// Set the padded leaf nodes
	tree.nodes[tree.Depth()-1] = padLeafs(leafs)
	parentNodes := tree.nodes[tree.Depth()-1]
	// Construct the Merkle tree bottom-up, starting from the leafs
	// Note the -1 due to 0-indexing the root level
	for level := tree.Depth() - 2; level >= 0; level-- {
		currentLevel := make([]Node, util.Ceil(uint(len(parentNodes)), 2))
		// Traverse the level left to right
		for i := 0; i+1 < len(parentNodes); i = i + 2 {
			currentLevel[i/2] = *computeNode(&parentNodes[i], &parentNodes[i+1])
		}
		tree.nodes[level] = currentLevel
		parentNodes = currentLevel
	}
	return tree
}

func padLeafs(leafs []Node) []Node {
	paddingAmount := (1 << util.Log2Ceil(uint64(len(leafs)))) - len(leafs)
	paddingLeafs := make([]Node, paddingAmount)
	// arrays are zeroed by default in Go
	return append(leafs, paddingLeafs...)
}

// Depth returns the amount of levels in the tree, including the root level and leafs.
// I.e. a tree with 3 leafs will have one leaf level, a middle level and a root, and hence Depth 3.
func (d TreeData) Depth() int {
	return len(d.nodes)
}

// LeafCount returns the amount of non-zero padded leafs in the tree
func (d TreeData) LeafCount() uint64 {
	return d.leafs
}

// Root returns a pointer to the root node
func (d TreeData) Root() *Node {
	return &d.nodes[0][0]
}

// Leafs return a slice consisting of all the leaf nodes, i.e. leaf data that has been hashed into a Node structure
func (d TreeData) Leafs() []Node {
	return d.nodes[len(d.nodes)-1]
}

// Node returns the node at given lvl and idx
func (d TreeData) Node(lvl int, idx uint64) *Node {
	res := d.nodes[lvl][int(idx)]
	return &res
}

// ValidateFromLeafs validates the structure of this Merkle tree, given the raw data elements the tree was constructed from
func (d TreeData) ValidateFromLeafs(leafs [][]byte) error {
	tree, err := GrowTree(leafs)
	if err != nil {
		return xerrors.Errorf("grow tree: %w", err)
	}
	if !reflect.DeepEqual(&d, tree) {
		return xerrors.Errorf("not equal to leafs")
	}
	return nil
}

// Validate returns true of this tree has been constructed correctly from the leafs (hashed data)
func (d TreeData) Validate() bool {
	tree := GrowTreeHashedLeafs(d.nodes[d.Depth()-1])
	return reflect.DeepEqual(d.nodes, tree.nodes)
}

// ConstructProof constructs a proof that a node at level lvl and index idx within that level, is contained in the tree.
// The root is in level 0 and the left-most node in a given level is indexed 0.
func (d TreeData) ConstructProof(lvl int, idx uint64) (*ProofData, error) {
	if lvl < 1 || lvl >= d.Depth() {
		return nil, fmt.Errorf("level is either below 1 or bigger than the tree supports")
	}

	// The proof consists of appropriate siblings up to and including layer 1
	proof := make([]Node, lvl)
	currentIdx := idx
	// Compute the node we wish to prove membership of to the root
	for currentLvl := lvl; currentLvl >= 1; currentLvl-- {
		// For error handling check that no index impossibly large is requested
		if uint64(len(d.nodes[currentLvl])) <= currentIdx {
			return nil, fmt.Errorf("the requested index %d on level %d does not exist in the tree", currentIdx, currentLvl)
		}
		// Only try to store the sibling node when it exists,
		// if the tree is not complete this might not always be the case
		if uint64(len(d.nodes[currentLvl])) > getSiblingIdx(currentIdx) {
			proof[currentLvl-1] = d.nodes[currentLvl][getSiblingIdx(currentIdx)]
		}
		// Set next index to be the parent
		currentIdx = currentIdx / 2
	}
	for i, j := 0, len(proof)-1; i < j; i, j = i+1, j-1 {
		proof[i], proof[j] = proof[j], proof[i]
	}

	return &ProofData{path: proof, index: idx}, nil
}

// Serialize serializes the MerkleTree into a byte slice
// This is done by first including the amount of leafs as a 64 bit unsigned int
// Then encode the tree, bottom-up, starting with the leafs as the amount of nodes in one level defines the amount of nodes in its parent level
// NOTE that correctness of the tree is NOT validated as part of this method
func (d TreeData) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint64(d.LeafCount()))
	if err != nil {
		log.Println("could not write the leaf count")
		return nil, err
	}
	// Encode from the leafs to make decoding easier
	for i := d.Depth() - 1; i >= 0; i-- {
		err = binary.Write(buf, binary.LittleEndian, d.nodes[i])
		if err != nil {
			log.Printf("could not write layer %d\n", i)
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// getSiblingIdx returns the index of the sibling
func getSiblingIdx(idx uint64) uint64 {
	if idx%2 == 0 {
		// If the index is even, then the node to the right should be returned
		return idx + 1
	} else {
		// Otherwise the node to the left should be returned
		return idx - 1
	}
}

func hashList(input [][]byte) []Node {
	digests := make([]Node, len(input))
	for i := 0; i < len(input); i++ {
		digests[i] = *TruncatedHash(input[i])
	}
	return digests
}

func TruncatedHash(data []byte) *Node {
	digest := sha256.Sum256(data)
	node := Node(digest)
	return truncate(&node)
}
