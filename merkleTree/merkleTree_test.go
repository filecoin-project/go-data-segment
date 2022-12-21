package merkleTree

import (
	"encoding/hex"
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

	assert.Equal(t, 2, len(tree.nodes))
	assert.Equal(t, 1, len(tree.nodes[0]))
	assert.Equal(t, 2, len(tree.nodes[1]))
	assert.Equal(t, expectedLeaf, tree.nodes[1][0].data[:])
	assert.Equal(t, expectedLeaf, tree.nodes[1][1].data[:])
	assert.Equal(t, expectedRoot, tree.nodes[0][0].data[:])
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
	expectedRightMiddleNode, err := hex.DecodeString("f38494aa397bf51c8491d20d8e34249958b19e57db5c7d29676c897c7f3ddf13")
	assert.Nil(t, err)
	expectedRoot, err := hex.DecodeString("ea0e5293bdbc7e98142f57d1cc83ec00592acb23515043641322bcc99a03b20b")
	assert.Nil(t, err)

	assert.Equal(t, 3, tree.depth())
	assert.Equal(t, 3, len(tree.nodes))
	assert.Equal(t, 1, len(tree.nodes[0]))
	assert.Equal(t, 2, len(tree.nodes[1]))
	assert.Equal(t, 3, len(tree.nodes[2]))
	assert.Equal(t, expectedLeaf, tree.nodes[2][0].data[:])
	assert.Equal(t, expectedLeaf, tree.nodes[2][1].data[:])
	assert.Equal(t, expectedLeaf, tree.nodes[2][2].data[:])
	assert.Equal(t, expectedLeftMiddleNode, tree.nodes[1][0].data[:])
	assert.Equal(t, expectedRightMiddleNode, tree.nodes[1][1].data[:])
	assert.Equal(t, expectedRoot, tree.nodes[0][0].data[:])
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

func TestLog2(t *testing.T) {
	assert.Equal(t, 0, log2Ceil(1))
	assert.Equal(t, 2, log2Ceil(4))
	assert.Equal(t, 3, log2Ceil(7))
}
