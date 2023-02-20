package merkletree

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeNode(t *testing.T) {
	assert.Equal(t, &Node{
		0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30, 0x27, 0x98, 0xef, 0x6e, 0xd3, 0x9, 0x97,
		0x9b, 0x43, 0x0, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8, 0xea, 0x98, 0x31, 0xa9, 0x27, 0x59,
		0xfb, 0xb},
		computeNode(&Node{}, &Node{}))
	assert.Equal(t, &Node{
		0xff, 0x55, 0xc9, 0x79, 0x76, 0xa8, 0x40, 0xb4, 0xce, 0xd9, 0x64, 0xed, 0x49, 0xe3, 0x79,
		0x45, 0x94, 0xba, 0x3f, 0x67, 0x52, 0x38, 0xb5, 0xfd, 0x25, 0xd2, 0x82, 0xb6, 0xf, 0x70,
		0xa1, 0x14},
		computeNode(&Node{0x1}, &Node{0x2})) // specified bytes are the lowest bytes
	assert.Equal(t, &Node{
		0x95, 0xe7, 0x3e, 0x86, 0x16, 0xbb, 0x92, 0x7b, 0xb0, 0x74, 0xee, 0x5, 0x5b, 0x12, 0x23,
		0xf3, 0xa0, 0x85, 0xf7, 0x10, 0xc, 0x97, 0x46, 0x8d, 0x92, 0xe6, 0x3a, 0x1c, 0x87, 0xaf,
		0x1c, 0x1a},
		computeNode(&Node{0x2}, &Node{0x1}))
}

// PUBLIC METHODS
func TestValidateLeafSunshine(t *testing.T) {
	for _, size := range []uint64{130, 255, 256, 257, 1000000} {
		tree := getTree(t, size)
		// Construct a proof of a leaf node
		proof, err := tree.ConstructProof(tree.Depth()-1, 0)
		assert.NoError(t, err)
		assert.NoError(t, proof.ValidateLeaf(getLeaf(t, 0), tree.Root()))
		proof, err = tree.ConstructProof(tree.Depth()-1, size-1)
		assert.NoError(t, err)
		assert.NoError(t, proof.ValidateLeaf(getLeaf(t, size-1), tree.Root()))
		proof, err = tree.ConstructProof(tree.Depth()-1, size/2-5)
		assert.NoError(t, err)
		assert.NoError(t, proof.ValidateLeaf(getLeaf(t, size/2-5), tree.Root()))
	}
}

func TestNegativeValidateLeaf(t *testing.T) {
	testAmounts := []uint64{68, 511, 512, 513, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		// Construct a proof of a leaf node
		proof, err := tree.ConstructProof(tree.Depth()-1, 4)
		assert.NoError(t, err)
		assert.NoError(t, proof.ValidateLeaf(getLeaf(t, 4), tree.Root()))
		for currentLvl := 0; currentLvl < tree.Depth()-1; currentLvl++ {
			for i := 0; i < NodeSize; i++ {
				// Corrupt a bit in a node
				// Note that modifying the most significant bits of the last byte will still result in failure even tough those bits should never be set
				proof.Path()[currentLvl][i] ^= 0b10000000
				assert.Error(t, proof.ValidateLeaf(getLeaf(t, 4), tree.Root()))
				// Reset the proof
				proof.Path()[currentLvl][i] ^= 0b10000000
			}
		}
	}
}

func TestValidateProofSubtree(t *testing.T) {
	testAmounts := []uint64{1300, 65535, 65536, 65537}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		for lvl := 1; lvl < tree.Depth(); lvl++ {
			// Test the smallest node in the level
			proof, err := tree.ConstructProof(lvl, 0)
			assert.NoError(t, err)
			assert.NoError(t, proof.ValidateSubtree(&tree.nodes[lvl][0], tree.Root()))

			// Test the largest node in the level
			proof, err = tree.ConstructProof(lvl, uint64(len(tree.nodes[lvl])-1))
			assert.NoError(t, err)
			assert.NoError(t, proof.ValidateSubtree(&tree.nodes[lvl][len(tree.nodes[lvl])-1], tree.Root()))

			// Test a node in the middle of the level
			proof, err = tree.ConstructProof(lvl, uint64(len(tree.nodes[lvl])/3))
			assert.NoError(t, err)
			assert.NoError(t, proof.ValidateSubtree(&tree.nodes[lvl][len(tree.nodes[lvl])/3], tree.Root()))
		}
	}
}

func TestNegativeValidateSubtree(t *testing.T) {
	testAmounts := []uint64{68, 511, 512, 513, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		for currentLvl := 1; currentLvl < tree.Depth()-1; currentLvl++ {
			// Construct a proof of the second to most right node
			idx := uint64(len(tree.nodes[currentLvl]) - 2)
			proof, err := tree.ConstructProof(currentLvl, idx)
			assert.NoError(t, err)
			// Corrupt a bit in a node
			proof.Path()[currentLvl/3][0] ^= 0b10000000
			assert.Error(t, proof.ValidateSubtree(&tree.nodes[currentLvl][idx], tree.Root()))
		}
	}
}

func TestNegativeSerializationProofEmpty(t *testing.T) {
	_, err := DeserializeProof(nil)
	assert.Error(t, err)
	_, err = DeserializeProof(make([]byte, 0))
	assert.Error(t, err)
}

func TestNegativeSerializationProofWrongSize(t *testing.T) {
	tree := getTree(t, 345)
	proof, err := tree.ConstructProof(5, 12)
	assert.NoError(t, err)
	encoded, err := proof.Serialize()
	assert.NoError(t, err)
	// Incorrect size of proof
	_, errDec := DeserializeProof(encoded[:2*BytesInInt+1])
	assert.Error(t, errDec)
}
