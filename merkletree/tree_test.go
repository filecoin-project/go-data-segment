package merkletree

import (
	"encoding/hex"
	"github.com/filecoin-project/go-data-segment/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

/**
SHA256 data is based on either empty input or RC4.55 test input, truncated to 254 bits
https://www.dlitz.net/crypto/shad256-test-vectors/
*/

// PUBLIC METHOD TESTS

func TestGrowTreeSunshine(t *testing.T) {
	singletonInput, err := hex.DecodeString("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e")
	assert.Nil(t, err)
	input := [][]byte{singletonInput, singletonInput}

	tree, err := GrowTree(input)
	assert.Nil(t, err)

	expectedLeaf, err := hex.DecodeString("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d302")
	assert.Nil(t, err)
	expectedRoot, err := hex.DecodeString("90a4a4c485b44abecda2c404e4a56df371c9f7c6f23f396f4c63903acf65d638")
	assert.Nil(t, err)

	assert.Equal(t, 2, tree.Depth())
	assert.Equal(t, 2, tree.LeafCount())
	assert.Equal(t, 2, len(tree.(data).nodes))
	assert.Equal(t, 1, len(tree.(data).nodes[0]))
	assert.Equal(t, 2, len(tree.(data).nodes[1]))
	assert.Equal(t, expectedLeaf, tree.(data).nodes[1][0].data[:])
	assert.Equal(t, expectedLeaf, tree.(data).nodes[1][1].data[:])
	assert.Equal(t, expectedRoot, (*tree.Root()).data[:])
}

func TestGrowTreeOdd(t *testing.T) {
	singletonInput, err := hex.DecodeString("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e")
	assert.Nil(t, err)
	// Construct a tree with 3 leafs
	input := [][]byte{singletonInput, singletonInput, singletonInput}

	tree, err := GrowTree(input)
	assert.Nil(t, err)
	expectedLeaf, err := hex.DecodeString("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d302")
	assert.Nil(t, err)
	expectedLeftMiddleNode, err := hex.DecodeString("90a4a4c485b44abecda2c404e4a56df371c9f7c6f23f396f4c63903acf65d638")
	assert.Nil(t, err)
	expectedRightMiddleNode, err := hex.DecodeString("01b2a169f7d05abbddc3d8f11cd675df31cc50b9d4324b17fb4ce17db987fd29")
	assert.Nil(t, err)
	expectedRoot, err := hex.DecodeString("088c2038d048af2e754df3cb8373cd9f7c15c8610f6e4a6b93b364cae5f85907")
	assert.Nil(t, err)

	assert.Equal(t, 3, tree.Depth())
	assert.Equal(t, 3, tree.LeafCount())
	assert.Equal(t, 3, len(tree.(data).nodes))
	assert.Equal(t, 1, len(tree.(data).nodes[0]))
	assert.Equal(t, 2, len(tree.(data).nodes[1]))
	assert.Equal(t, 4, len(tree.(data).nodes[2]))
	assert.Equal(t, expectedLeaf, tree.(data).nodes[2][0].data[:])
	assert.Equal(t, expectedLeaf, tree.(data).nodes[2][1].data[:])
	assert.Equal(t, expectedLeaf, tree.(data).nodes[2][2].data[:])
	assert.Equal(t, expectedLeftMiddleNode, tree.(data).nodes[1][0].data[:])
	assert.Equal(t, expectedRightMiddleNode, tree.(data).nodes[1][1].data[:])
	assert.Equal(t, expectedRoot, (*tree.Root()).data[:])
}

func TestGrowTreeSoak(t *testing.T) {
	for amount := 4; amount < 125; amount++ {
		tree := getTree(t, amount)

		assert.Equal(t, 1+util.Log2Ceil(uint64(amount)), tree.Depth())
		// LeafCount should have "amount" elements
		assert.Equal(t, amount, tree.LeafCount())
	}
}

func TestConstructProof(t *testing.T) {
	tree := getTree(t, 130)

	// Construct a proof of a leaf node
	proof, err := tree.ConstructProof(tree.Depth()-1, 55)
	assert.Nil(t, err)

	assert.Equal(t, proof.Level(), util.Log2Ceil(uint64(tree.LeafCount())))
	assert.Equal(t, proof.Index(), 55)
	assert.Equal(t, len(proof.Path()), tree.Depth()-1)
}

func TestValidateFromLeafs(t *testing.T) {
	testAmounts := []int{33, 235, 543}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		leafs := getLeafs(t, 0, amount)
		assert.True(t, tree.ValidateFromLeafs(leafs))
	}
}

func TestValidate(t *testing.T) {
	testAmounts := []int{80, 1023, 1024, 1025}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		assert.True(t, tree.Validate())
	}
}

func TestNegativeValidate(t *testing.T) {
	testAmounts := []int{42, 1023, 1024, 1025}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)

		// Corrupt a bit in a node
		tree.(data).nodes[3][3].data[3] ^= 0b10000000
		assert.False(t, tree.Validate())
	}
}

func TestFailureGrowTree(t *testing.T) {
	_, err := GrowTree(nil)
	assert.NotNil(t, err)
	_, err = GrowTree([][]byte{})
	assert.NotNil(t, err)
}

func TestFailureConstructProof(t *testing.T) {
	tree := getTree(t, 20)
	_, err := tree.ConstructProof(0, 0)
	assert.NotNil(t, err)
	_, err = tree.ConstructProof(10, 0)
	assert.NotNil(t, err)
	_, err = tree.ConstructProof(2, 20)
	assert.NotNil(t, err)
	_, err = tree.ConstructProof(2, -1)
	assert.NotNil(t, err)
}

func TestFailureValidate(t *testing.T) {
	tree := getTree(t, 20)
	assert.False(t, tree.ValidateFromLeafs(nil))
	assert.False(t, tree.ValidateFromLeafs([][]byte{}))
	notEnough := make([][]byte, 19)
	assert.False(t, tree.ValidateFromLeafs(notEnough))
}

// PRIVATE METHOD TESTS

// TestTruncatedHash is tested against SHA256 test vector for the empty input
func TestTruncatedHash(t *testing.T) {
	var input [0]byte
	node := truncatedHash(input[:])
	// SHA256 empty input
	expected := [256 / 8]byte{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}
	expected[256/8-1] &= 0b00111111

	assert.Equal(t, expected, node.data)
}

func TestComputeNode(t *testing.T) {
	var rawInput [0]byte
	inputNode := truncatedHash(rawInput[:])
	result := computeNode(inputNode, inputNode)

	expected, err := hex.DecodeString("db5bf619105c0640e070e01d925cfe1243cdc742609794eb1018ae9e7284fa1d")
	assert.Nil(t, err)

	assert.Equal(t, expected, result.data[:])
}

func TestComputeNodeFullInput(t *testing.T) {
	// Note most significant bit of last byte is NOT set
	singletonInput, err := hex.DecodeString("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d302")
	assert.Nil(t, err)
	nodeInput := Node{data: *(*[digestBytes]byte)(singletonInput)}
	result := computeNode(&nodeInput, &nodeInput)

	// Truncated hash digest of input nodes (which are each truncated to 254 bits)
	expected, err := hex.DecodeString("90a4a4c485b44abecda2c404e4a56df371c9f7c6f23f396f4c63903acf65d638")
	assert.Nil(t, err)
	assert.Equal(t, expected, result.data[:])
}

func TestTruncatedHashTruncation(t *testing.T) {
	// RC4.55 test data, note the two least significant bits have been truncated
	truncatedInput, err := hex.DecodeString("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb621e")
	assert.Nil(t, err)

	truncatedHash := truncatedHash(truncatedInput)
	// Truncated hash digest of input nodes (which are each truncated to 254 bits)
	expected, err := hex.DecodeString("ab54eaeefe01cd1396247efa4ac59029b4c44c1729f5200f0693645d427db502")
	assert.Nil(t, err)
	assert.Equal(t, expected[digestBytes-1]&0b00111111, truncatedHash.data[digestBytes-1])
	assert.Equal(t, expected, truncatedHash.data[:])
}

func TestHashList(t *testing.T) {
	// RC4.55 test data
	singletonInput, err := hex.DecodeString("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e")
	assert.Nil(t, err)
	input := [][]byte{singletonInput, singletonInput}

	result := hashList(input)

	expected, err := hex.DecodeString("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d302")
	assert.Nil(t, err)

	for i := 0; i < len(input); i++ {
		assert.Equal(t, expected, result[i].data[:])
	}
}

// HELPER METHODS
// Builds an arbitrary tree of equal leaf nodes.
// Each leaf is defined to be the base XORed with their index
func getTree(t *testing.T, leafs int) MerkleTree {
	leafData := getLeafs(t, 0, leafs)
	tree, err := GrowTree(leafData)
	assert.Nil(t, err)
	return tree
}

func getLeafs(t *testing.T, startIdx int, amount int) [][]byte {
	leafs := make([][]byte, amount)
	for i := 0; i < amount; i++ {
		leafs[i] = getLeaf(t, i+startIdx)
	}
	return leafs
}

// getLeaf returns a leaf which is 0xdeadbeef XORed with idx
func getLeaf(t *testing.T, idx int) []byte {
	singletonInput, err := hex.DecodeString("deadbeef")
	assert.Nil(t, err)
	singletonInput[0] ^= byte(idx)
	return singletonInput
}
