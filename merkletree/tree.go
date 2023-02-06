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
)

const digestBytes = 32

// BytesInInt represents the amount of bytes used to encode an int
const BytesInInt int = 64 / 8

// MerkleTree represents a Merkle tree which can be used to construct proof of containment for either leafs, subtrees or a sequence of leafs (subtrees)
type MerkleTree interface {
	// Depth returns the Depth of the tree. A single-node tree has Depth 1
	Depth() int
	// LeafCount returns the amount of leafs in the Merkle tree
	LeafCount() int
	// Root returns the root node of the tree
	Root() *Node
	// Leafs returns all the leaf nodes in the tree
	Leafs() []Node
	// Node returns the node at given lvl and idx
	Node(int, int) *Node
	// ConstructProof constructs a Merkle proof of the subtree (or leaf) at level lvl with index idx.
	// level 0 is the root and index 0 is the left-most node in a level.
	ConstructProof(lvl int, idx int) (MerkleProof, error)
	// ConstructBatchedProof constructs a batched Merkle proof of the nodes from and including leftLvl, leftIdx, to and including rightLvl, rightIdx.
	// That is, if leftLvl, or rightLvl, is not the leaf-level, then the proof is of the entire subtree from leftLvl at leftIdx to rightLvl at rightIdx
	// Level 0 is the root and index 0 is the left-most node in a level.
	ConstructBatchedProof(leftLvl int, leftIdx int, rightLvl int, rightIdx int) (BatchedMerkleProof, error)
	// ValidateFromLeafs checks that the Merkle tree is correctly constructed based on all the leafData
	ValidateFromLeafs(leafData [][]byte) bool
	// Validate checks that the Merkle tree is correctly constructed, based on the internal nodes
	Validate() bool
	// Serialize serializes the MerkleTree into a byte slice
	Serialize() ([]byte, error)
}

type data struct {
	// nodes start from root and go down left-to-right
	// thus len(nodes[0]) = 1, len(nodes[1]) = 2, etc.
	nodes [][]Node
	// leafs is the amount of raw leafs being used. I.e. without padding to nearest two-power
	leafs int
}

type Node struct {
	Data [digestBytes]byte
}

// newBareTree allocates that memory needed to construct a tree with a specific amount of leafs.
// The construction rounds the amount of leafs up to the nearest two-power with zeroed nodes to ensure
// that the tree is perfect and hence all internal node's have well-defined children.
func newBareTree(leafs int) data {
	adjustedLeafs := 1 << util.Log2Ceil(uint64(leafs))
	var tree data
	tree.nodes = make([][]Node, 1+util.Log2Ceil(uint64(adjustedLeafs)))
	tree.leafs = leafs
	for i := 0; i <= util.Log2Ceil(uint64(adjustedLeafs)); i++ {
		tree.nodes[i] = make([]Node, 1<<i)
	}
	return tree
}

// DeserializeTree deserializes a serialized Merkle tree
// This is done by first reading the amount of leafs as a 64 bit int
// Then decoding the tree, bottom-up, starting with the leafs as the amount of nodes in one level defines the amount of nodes in its parent level
// NOTE that correctness of the tree is NOT validated as part of this method
func DeserializeTree(tree []byte) (MerkleTree, error) {
	if tree == nil || len(tree) < BytesInInt {
		log.Println("no tree encoded")
		return data{}, errors.New("no tree encoded")
	}
	lvlSize := int(binary.LittleEndian.Uint64(tree[:BytesInInt]))
	if lvlSize <= 0 {
		log.Printf("amount of leafs must be positive:  %d\n", lvlSize)
		return data{}, errors.New("amount of leafs must be positive")
	}
	decoded := newBareTree(lvlSize)
	ctr := BytesInInt
	// Decode from the leafs
	for i := decoded.Depth() - 1; i >= 0; i-- {
		if len(tree) < ctr+fr32.BytesNeeded*lvlSize {
			log.Printf("error in tree encoding. Does not contain level %d\n", i)
			return data{}, errors.New("error in tree encoding")
		}
		currentLvl := make([]Node, lvlSize)
		for j := 0; j < lvlSize; j++ {
			nodeBytes := (*[fr32.BytesNeeded]byte)(tree[ctr : ctr+fr32.BytesNeeded])
			currentLvl[j] = Node{Data: *nodeBytes}
			ctr += fr32.BytesNeeded
		}
		decoded.nodes[i] = currentLvl
		// The amount of nodes in the parent level is half, rounded up
		lvlSize = util.Ceil(uint(lvlSize), 2)
	}
	return decoded, nil
}

// GrowTree constructs a Merkle from a list of leafData, the data of a given leaf is represented as a byte slice
// The construction rounds the amount of leafs up to the nearest two-power with zeroed nodes to ensure
// that the tree is perfect and hence all internal node's have well-defined children.
// TODO should things be hard-coded to work on 32 byte leafs?
func GrowTree(leafData [][]byte) (MerkleTree, error) {
	if len(leafData) == 0 {
		return nil, errors.New("empty input")
	}
	leafLevel := hashList(leafData)
	return GrowTreeHashedLeafs(leafLevel), nil
}

// GrowTreeHashedLeafs constructs a tree from leafs nodes, i.e. leaf data that has been hashed to construct a Node
func GrowTreeHashedLeafs(leafs []Node) MerkleTree {
	tree := newBareTree(len(leafs))
	tree.leafs = len(leafs)
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
	for i := 0; i < paddingAmount; i++ {
		// None existing leafs gets defined to be 32 0-bytes
		paddingLeafs[i] = Node{Data: [32]byte{}}
	}
	return append(leafs, paddingLeafs...)
}

// Depth returns the amount of levels in the tree, including the root level and leafs.
// I.e. a tree with 3 leafs will have one leaf level, a middle level and a root, and hence Depth 3.
func (d data) Depth() int {
	return len(d.nodes)
}

// LeafCount returns the amount of non-zero padded leafs in the tree
func (d data) LeafCount() int {
	return d.leafs
}

// Root returns a pointer to the root node
func (d data) Root() *Node {
	return &d.nodes[0][0]
}

// Leafs return a slice consisting of all the leaf nodes, i.e. leaf data that has been hashed into a Node structure
func (d data) Leafs() []Node {
	return d.nodes[len(d.nodes)-1]
}

// Node returns the node at given lvl and idx
func (d data) Node(lvl int, idx int) *Node {
	return &d.nodes[lvl][idx]
}

// ValidateFromLeafs validates the structure of this Merkle tree, given the raw data elements the tree was constructed from
func (d data) ValidateFromLeafs(leafs [][]byte) bool {
	tree, err := GrowTree(leafs)
	if err != nil {
		log.Println("could not grow tree")
		return false
	}
	return reflect.DeepEqual(d, tree)
}

// Validate returns true of this tree has been constructed correctly from the leafs (hashed data)
func (d data) Validate() bool {
	tree := GrowTreeHashedLeafs(d.nodes[d.Depth()-1])
	return reflect.DeepEqual(d.nodes, tree.(data).nodes)
}

// ConstructProof constructs a proof that a node at level lvl and index idx within that level, is contained in the tree.
// The root is in level 0 and the left-most node in a given level is indexed 0.
func (d data) ConstructProof(lvl int, idx int) (MerkleProof, error) {
	if lvl < 1 || lvl >= d.Depth() {
		log.Printf("level is either below 1 or bigger than the tree supports\n")
		return nil, fmt.Errorf("level is either below 1 or bigger than the tree supports")
	}
	if idx < 0 {
		log.Printf("the requested index %d is negative\n", idx)
		return nil, fmt.Errorf("the requested index %d is negative", idx)
	}
	// The proof consists of appropriate siblings up to and including layer 1
	proof := make([]Node, lvl)
	currentIdx := idx
	// Compute the node we wish to prove membership of to the root
	for currentLvl := lvl; currentLvl >= 1; currentLvl-- {
		// For error handling check that no index impossibly large is requested
		if len(d.nodes[currentLvl]) <= currentIdx {
			log.Printf("the requested index %d on level %d does not exist in the tree\n", currentIdx, currentLvl)
			return nil, fmt.Errorf("the requested index %d on level %d does not exist in the tree", currentIdx, currentLvl)
		}
		// Only try to store the sibling node when it exists,
		// if the tree is not complete this might not always be the case
		if len(d.nodes[currentLvl]) > getSiblingIdx(currentIdx) {
			proof[currentLvl-1] = d.nodes[currentLvl][getSiblingIdx(currentIdx)]
		}
		// Set next index to be the parent
		currentIdx = currentIdx / 2
	}
	return proofData{path: proof, lvl: lvl, idx: idx}, nil
}

// ConstructBatchedProof constructs a proof that a sequence of leafs are contained in the tree. Either through a subtree or a (hashed) leaf.
// The proof contains everything captured by the node in leftLvl level at index leftIdx up to and INCLUDING everything
// contained by the node in rightLvl level and rightIdx index.
// The root is in level 0 and the left-most node in a given level is indexed 0.
func (d data) ConstructBatchedProof(leftLvl int, leftIdx int, rightLvl int, rightIdx int) (BatchedMerkleProof, error) {
	if leftLvl < 1 || leftLvl >= d.Depth() || rightLvl < 1 || rightLvl >= d.Depth() {
		log.Println("a level is either below 1 or bigger than the tree supports")
		return batchedProofData{}, errors.New("a level is either below 1 or bigger than the tree supports")
	}
	if leftIdx < 0 || rightIdx < 0 {
		log.Println("a requested index is negative")
		return batchedProofData{}, errors.New("a requested index is negative")
	}
	// Construct individual proofs
	leftProof, err := d.ConstructProof(leftLvl, leftIdx)
	if err != nil {
		return batchedProofData{}, err
	}
	rightProof, err := d.ConstructProof(rightLvl, rightIdx)
	if err != nil {
		return batchedProofData{}, err
	}
	return CreateBatchedProof(leftProof, rightProof), nil
}

// Serialize serializes the MerkleTree into a byte slice
// This is done by first including the amount of leafs as a 64 bit unsigned int
// Then encode the tree, bottom-up, starting with the leafs as the amount of nodes in one level defines the amount of nodes in its parent level
// NOTE that correctness of the tree is NOT validated as part of this method
func (d data) Serialize() ([]byte, error) {
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
func getSiblingIdx(idx int) int {
	if idx%2 == 0 {
		// If the index is even, then the node to the right should be returned
		return idx + 1
	} else {
		// Otherwise the node to the left should be returned
		return idx - 1
	}
}

// computeNode computes a new internal node in a tree, from its left and right children
func computeNode(left *Node, right *Node) *Node {
	toHash := make([]byte, 2*digestBytes)
	copy(toHash, (*left).Data[:])
	copy(toHash[digestBytes:], (*right).Data[:])
	return TruncatedHash(toHash)
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
	digest[(256/8)-1] &= 0b00111111
	node := Node{digest}
	return &node
}
