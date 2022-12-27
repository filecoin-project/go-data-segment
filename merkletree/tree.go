package merkletree

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/filecoin-project/go-data-segment/util"
	"log"
	"reflect"
)

const digestBits = 254
const digestBytes = 32

type MerkleTree interface {
	// Depth returns the Depth of the tree. A single-node tree has Depth 1
	Depth() int
	// LeafCount returns the amount of leafs in the Merkle tree
	LeafCount() int
	// Root returns the root node of the tree
	Root() *Node
	// Leafs returns all the leaf nodes in the tree
	Leafs() []Node
	// ConstructProof constructs a Merkle proof of the subtree (or leaf) at level lvl with index idx.
	// level 0 is the root and index 0 is the left-most node in a level.
	ConstructProof(lvl int, idx int) (MerkleProof, error)
	// ConstructBatchedProof constructs a batched Merkle proof of the nodes from and including leftLvl, leftIdx, to and including rightLvl, rightIdx.
	// That is, if leftLvl, or rightLvl, is not the leaf-level, then the proof is of the entire subtree from leftLvl at leftIdx to rightLvl at rightIdx
	// Level 0 is the root and index 0 is the left-most node in a level.
	ConstructBatchedProof(leftLvl int, leftIdx int, rightLvl int, rightIdx int) (BatchedMerkleProof, error)
	// ValidateFromLeafs checks that the Merkle tree is correctly constructed based on all the leaf data
	ValidateFromLeafs(leafData [][]byte) bool
	// Validate checks that the Merkle tree is correctly constructed, based on the internal nodes
	Validate() bool
}

type data struct {
	// nodes start from root and go down left-to-right
	// thus len(nodes[0]) = 1, len(nodes[1]) = 2, etc.
	nodes [][]Node
}

type Node struct {
	data [digestBytes]byte
}

func NewBareTree(elements int) MerkleTree {
	var tree data
	tree.nodes = make([][]Node, 1+util.Log2Ceil(elements))
	for i := 0; i <= util.Log2Ceil(elements); i++ {
		tree.nodes[i] = make([]Node, 1<<i)
	}
	return tree
}

func GrowTree(leafData [][]byte) (MerkleTree, error) {
	var tree MerkleTree
	if leafData == nil || len(leafData) == 0 {
		return tree, errors.New("empty input")
	}
	leafLevel := hashList(leafData)
	return growTreeHashedLeafs(leafLevel), nil
}

func growTreeHashedLeafs(leafs []Node) MerkleTree {
	tree := NewBareTree(len(leafs))
	// Set the leaf nodes
	tree.(data).nodes[util.Log2Ceil(len(leafs))] = leafs
	preLevel := leafs
	// Construct the Merkle tree bottom-up, starting from the leafs
	// Note the -1 due to 0-indexing the root level
	for level := util.Log2Ceil(len(leafs)) - 1; level >= 0; level-- {
		currentLevel := make([]Node, util.Ceil(len(preLevel), 2))
		// Traverse the level left to right
		for i := 0; i+1 < len(preLevel); i = i + 2 {
			currentLevel[i/2] = *computeNode(&preLevel[i], &preLevel[i+1])
		}
		// Handle the edge case where the tree is not complete, i.e. there is an odd number of leafs
		// This is done by hashing the content of the node and letting it be its own parent
		if len(preLevel)%2 == 1 {
			currentLevel[util.Ceil(len(preLevel), 2)-1] = *truncatedHash(preLevel[len(preLevel)-1].data[:])
		}
		tree.(data).nodes[level] = currentLevel
		preLevel = currentLevel
	}
	return tree
}

// Depth returns the amount of levels in the tree, including the root level and leafs.
// I.e. a tree with 3 leafs will have one leaf level, a middle level and a root, and hence Depth 3.
func (d data) Depth() int {
	return len(d.nodes)
}

func (d data) LeafCount() int {
	return len(d.nodes[len(d.nodes)-1])
}

func (d data) Root() *Node {
	return &d.nodes[0][0]
}

func (d data) Leafs() []Node {
	return d.nodes[len(d.nodes)-1]
}

func (d data) ValidateFromLeafs(leafs [][]byte) bool {
	tree, err := GrowTree(leafs)
	if err != nil {
		log.Println("could not grow tree")
		return false
	}
	return reflect.DeepEqual(d, tree)
}

func (d data) Validate() bool {
	tree := growTreeHashedLeafs(d.nodes[d.Depth()-1])
	return reflect.DeepEqual(d.nodes, tree.(data).nodes)
}

func (d data) ConstructProof(lvl int, idx int) (MerkleProof, error) {
	if lvl < 1 || lvl >= d.Depth() {
		log.Println("level is either below 1 or bigger than the tree supports")
		return ProofData{}, errors.New("level is either below 1 or bigger than the tree supports")
	}
	if idx < 0 {
		log.Println(fmt.Sprintf("the requested index %d is negative", idx))
		return ProofData{}, errors.New(fmt.Sprintf("the requested index %d is negative", idx))
	}
	// The proof consists of appropriate siblings up to and including layer 1
	proof := make([]Node, lvl)
	currentIdx := idx
	// Compute the node we wish to prove membership of to the root
	for currentLvl := lvl; currentLvl >= 1; currentLvl-- {
		// For error handling check that no index impossibly large is requested
		if len(d.nodes[currentLvl]) <= currentIdx {
			log.Println(fmt.Sprintf("the requested index %d on level %d does not exist in the tree", currentIdx, currentLvl))
			return ProofData{}, errors.New(fmt.Sprintf("the requested index %d on level %d does not exist in the tree", currentIdx, currentLvl))
		}
		// Only try to store the sibling node when it exists,
		// if the tree is not complete this might not always be the case
		if len(d.nodes[currentLvl]) > getSiblingIdx(currentIdx) {
			proof[currentLvl-1] = d.nodes[currentLvl][getSiblingIdx(currentIdx)]
		}
		// Set next index to be the parent
		currentIdx = currentIdx / 2
	}
	return ProofData{path: proof, lvl: lvl, idx: idx}, nil
}

func (d data) ConstructBatchedProof(leftLvl int, leftIdx int, rightLvl int, rightIdx int) (BatchedMerkleProof, error) {
	var factory BatchedProofFactory = CreateEmptyBatchedProof
	if leftLvl < 1 || leftLvl >= d.Depth() || rightLvl < 1 || rightLvl >= d.Depth() {
		log.Println("a level is either below 1 or bigger than the tree supports")
		return factory(), errors.New("a level is either below 1 or bigger than the tree supports")
	}
	if leftIdx < 0 || rightIdx < 0 {
		log.Println("a requested index is negative")
		return factory(), errors.New("a requested index is negative")
	}
	// Construct individual proofs
	leftProof, err := d.ConstructProof(leftLvl, leftIdx)
	if err != nil {
		return factory(), err
	}
	rightProof, err := d.ConstructProof(rightLvl, rightIdx)
	if err != nil {
		return factory(), err
	}
	return CreateBatchedProof(leftProof, rightProof), nil
}

// Returns the index of the sibling
func getSiblingIdx(idx int) int {
	if idx%2 == 0 {
		// If the index is even, then the node to the right should be returned
		return idx + 1
	} else {
		// Otherwise the node to the left should be returned
		return idx - 1
	}
}

func computeNode(left *Node, right *Node) *Node {
	toHash := make([]byte, 2*digestBytes)
	copy(toHash, (*left).data[:])
	copy(toHash[digestBytes:], (*right).data[:])
	return truncatedHash(toHash)
}

func hashList(input [][]byte) []Node {
	digests := make([]Node, len(input))
	for i := 0; i < len(input); i++ {
		digests[i] = *truncatedHash(input[i])
	}
	return digests
}

func truncatedHash(data []byte) *Node {
	digst := sha256.Sum256(data)
	digst[(256/8)-1] &= 0b00111111
	node := Node{digst}
	return &node
}
