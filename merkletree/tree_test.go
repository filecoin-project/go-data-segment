package merkletree

import (
	"encoding/hex"
	"testing"

	"github.com/filecoin-project/go-data-segment/util"
	"github.com/stretchr/testify/assert"
)

/**
SHA256 data is based on either empty input or RC4.55 test input, truncated to 254 bits
https://www.dlitz.net/crypto/shad256-test-vectors/
*/

// PUBLIC METHOD TESTS

func TestGrowTreeSunshine(t *testing.T) {
	singletonInput, err := hex.DecodeString("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e")
	assert.NoError(t, err)
	input := [][]byte{singletonInput, singletonInput}

	tree, err := GrowTree(input)
	assert.NoError(t, err)

	expectedLeaf, err := hex.DecodeString("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d302")
	assert.NoError(t, err)
	expectedRoot, err := hex.DecodeString("90a4a4c485b44abecda2c404e4a56df371c9f7c6f23f396f4c63903acf65d638")
	assert.NoError(t, err)

	assert.Equal(t, 2, tree.Depth())
	assert.Equal(t, uint64(2), tree.LeafCount())
	assert.Equal(t, 2, len(tree.nodes))
	assert.Equal(t, 1, len(tree.nodes[0]))
	assert.Equal(t, 2, len(tree.nodes[1]))
	assert.Equal(t, expectedLeaf, tree.nodes[1][0][:])
	assert.Equal(t, expectedLeaf, tree.nodes[1][1][:])
	assert.Equal(t, expectedRoot, (*tree.Root())[:])
}

func TestGrowTreeOdd(t *testing.T) {
	singletonInput, err := hex.DecodeString("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e")
	assert.NoError(t, err)
	// Construct a tree with 3 leafs
	input := [][]byte{singletonInput, singletonInput, singletonInput}

	tree, err := GrowTree(input)
	assert.NoError(t, err)
	expectedLeaf, err := hex.DecodeString("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d302")
	assert.NoError(t, err)
	expectedLeftMiddleNode, err := hex.DecodeString("90a4a4c485b44abecda2c404e4a56df371c9f7c6f23f396f4c63903acf65d638")
	assert.NoError(t, err)
	expectedRightMiddleNode, err := hex.DecodeString("01b2a169f7d05abbddc3d8f11cd675df31cc50b9d4324b17fb4ce17db987fd29")
	assert.NoError(t, err)
	expectedRoot, err := hex.DecodeString("088c2038d048af2e754df3cb8373cd9f7c15c8610f6e4a6b93b364cae5f85907")
	assert.NoError(t, err)

	assert.Equal(t, 3, tree.Depth())
	assert.Equal(t, uint64(3), tree.LeafCount())
	assert.Equal(t, 3, len(tree.nodes))
	assert.Equal(t, 1, len(tree.nodes[0]))
	assert.Equal(t, 2, len(tree.nodes[1]))
	assert.Equal(t, 4, len(tree.nodes[2]))
	assert.Equal(t, expectedLeaf, tree.nodes[2][0][:])
	assert.Equal(t, expectedLeaf, tree.nodes[2][1][:])
	assert.Equal(t, expectedLeaf, tree.nodes[2][2][:])
	assert.Equal(t, expectedLeftMiddleNode, tree.nodes[1][0][:])
	assert.Equal(t, expectedRightMiddleNode, tree.nodes[1][1][:])
	assert.Equal(t, expectedRoot, (*tree.Root())[:])
}

func TestGrowTreeSoak(t *testing.T) {
	for amount := uint64(4); amount < 125; amount++ {
		tree := getTree(t, amount)

		assert.Equal(t, 1+util.Log2Ceil(uint64(amount)), tree.Depth())
		// LeafCount should have "amount" elements
		assert.Equal(t, amount, tree.LeafCount())
	}
}

func TestTreeSerialization(t *testing.T) {
	testAmounts := []uint64{2, 3, 4, 55, 555}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		assert.True(t, tree.Validate())
		encoded, errEnc := tree.Serialize()
		assert.NoError(t, errEnc)
		assert.NotNil(t, encoded)
		decoded, errDec := DeserializeTree(encoded)
		assert.NoError(t, errDec)
		assert.NotNil(t, decoded)
		assert.Equal(t, tree, decoded)
		assert.True(t, decoded.Validate())
	}
}

func TestConstructProof(t *testing.T) {
	tree := getTree(t, 130)

	// Construct a proof of a leaf node
	proof, err := tree.ConstructProof(tree.Depth()-1, 55)
	assert.NoError(t, err)

	assert.Equal(t, proof.Depth(), util.Log2Ceil(uint64(tree.LeafCount())))
	assert.Equal(t, proof.Index, uint64(55))
	assert.Equal(t, len(proof.Path), tree.Depth()-1)
}

func TestValidateFromLeafs(t *testing.T) {
	testAmounts := []uint64{33, 235, 543}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		leafs := getLeafs(t, 0, amount)
		assert.NoError(t, tree.ValidateFromLeafs(leafs))
	}
}

func TestValidate(t *testing.T) {
	testAmounts := []uint64{80, 1023, 1024, 1025}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		assert.True(t, tree.Validate())
	}
}

func TestNegativeValidate(t *testing.T) {
	testAmounts := []uint64{42, 1023, 1024, 1025}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)

		// Corrupt a bit in a node
		tree.nodes[3][3][3] ^= 0b10000000
		assert.False(t, tree.Validate())
	}
}

func TestNegativeGrowTree(t *testing.T) {
	_, err := GrowTree(nil)
	assert.NotNil(t, err)
	_, err = GrowTree([][]byte{})
	assert.NotNil(t, err)
}

func TestNegativeSerializationEmptyTree(t *testing.T) {
	tree := getTree(t, 1)
	tree.nodes[tree.Depth()-1] = make([]Node, 0)
	encoded, err := tree.Serialize()
	assert.NoError(t, err)
	_, errDec := DeserializeTree(encoded)
	assert.NotNil(t, errDec)
}

func TestNegativeSerializationWrongSize(t *testing.T) {
	tree := getTree(t, 128)
	tree.nodes[tree.Depth()-2] = make([]Node, 1)
	encoded, err := tree.Serialize()
	assert.NoError(t, err)
	_, errDec := DeserializeTree(encoded)
	assert.NotNil(t, errDec)
}

func TestNegativeDeserializationNilTree(t *testing.T) {
	_, errDec := DeserializeTree(nil)
	assert.NotNil(t, errDec)
	_, errDec = DeserializeTree(make([]byte, 0))
	assert.NotNil(t, errDec)
}

func TestNegativeConstructProof(t *testing.T) {
	tree := getTree(t, 20)
	_, err := tree.ConstructProof(0, 0)
	assert.NotNil(t, err)
	_, err = tree.ConstructProof(10, 0)
	assert.NotNil(t, err)
	_, err = tree.ConstructProof(2, 20)
	assert.NotNil(t, err)
}

func TestNegativeValidateFromLeafs(t *testing.T) {
	tree := getTree(t, 20)
	assert.Error(t, tree.ValidateFromLeafs(nil))
	assert.Error(t, tree.ValidateFromLeafs([][]byte{}))
	notEnough := make([][]byte, 19)
	assert.Error(t, tree.ValidateFromLeafs(notEnough))
}

// PRIVATE METHOD TESTS

// TestTruncatedHash is tested against SHA256 test vector for the empty input
func TestTruncatedHash(t *testing.T) {
	var input [0]byte
	node := TruncatedHash(input[:])
	// SHA256 empty input
	expected := [256 / 8]byte{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}
	expected[256/8-1] &= 0b00111111

	assert.Equal(t, expected[:], node[:])
}

func TestComputeNodeFullInput(t *testing.T) {
	// Note most significant bit of last byte is NOT set
	singletonInput, err := hex.DecodeString("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d302")
	assert.NoError(t, err)
	nodeInput := *(*Node)(singletonInput)
	result := computeNode(&nodeInput, &nodeInput)

	// Truncated hash digest of input nodes (which are each truncated to 254 bits)
	expected, err := hex.DecodeString("90a4a4c485b44abecda2c404e4a56df371c9f7c6f23f396f4c63903acf65d638")
	assert.NoError(t, err)
	assert.Equal(t, expected, result[:])
}

func TestTruncatedHashTruncation(t *testing.T) {
	// RC4.55 test data, note the two least significant bits have been truncated
	truncatedInput, err := hex.DecodeString("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb621e")
	assert.NoError(t, err)

	truncatedHash := TruncatedHash(truncatedInput)
	// Truncated hash digest of input nodes (which are each truncated to 254 bits)
	expected, err := hex.DecodeString("ab54eaeefe01cd1396247efa4ac59029b4c44c1729f5200f0693645d427db502")
	assert.NoError(t, err)
	assert.Equal(t, expected[NodeSize-1]&0b00111111, truncatedHash[NodeSize-1])
	assert.Equal(t, expected, truncatedHash[:])
}

func TestHashList(t *testing.T) {
	// RC4.55 test data
	singletonInput, err := hex.DecodeString("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e")
	assert.NoError(t, err)
	input := [][]byte{singletonInput, singletonInput}

	result := hashList(input)

	expected, err := hex.DecodeString("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d302")
	assert.NoError(t, err)

	for i := 0; i < len(input); i++ {
		assert.Equal(t, expected, result[i][:])
	}
}

// HELPER METHODS
// Builds an arbitrary tree of equal leaf nodes.
// Each leaf is defined to be the base XORed with their index
func getTree(t *testing.T, leafs uint64) *TreeData {
	leafData := getLeafs(t, 0, leafs)
	tree, err := GrowTree(leafData)
	assert.NoError(t, err)
	return tree
}

func getLeafs(t *testing.T, startIdx uint64, amount uint64) [][]byte {
	leafs := make([][]byte, amount)
	for i := uint64(0); i < amount; i++ {
		leafs[i] = getLeaf(t, i+startIdx)
	}
	return leafs
}

// getLeaf returns a leaf which is 0xdeadbeef XORed with idx
func getLeaf(t *testing.T, idx uint64) []byte {
	singletonInput, err := hex.DecodeString("deadbeef")
	assert.NoError(t, err)
	singletonInput[0] ^= byte(idx)
	return singletonInput
}
