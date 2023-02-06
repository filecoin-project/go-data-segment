package merkletree

import (
	"reflect"
	"testing"

	"github.com/filecoin-project/go-data-segment/util"
	"github.com/stretchr/testify/assert"
)

// PUBLIC METHODS
func TestValidateLeafSunshine(t *testing.T) {
	testAmounts := []uint64{130, 255, 256, 257, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		// Construct a proof of a leaf node
		proof, err := tree.ConstructProof(tree.Depth()-1, 0)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateLeaf(getLeaf(t, 0), tree.Root()))
		proof, err = tree.ConstructProof(tree.Depth()-1, amount-1)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateLeaf(getLeaf(t, amount-1), tree.Root()))
		proof, err = tree.ConstructProof(tree.Depth()-1, amount/2-5)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateLeaf(getLeaf(t, amount/2-5), tree.Root()))
	}
}

func TestProofSerialization(t *testing.T) {
	testAmounts := []uint64{2, 3, 4, 55, 555}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		proof, errProof := tree.ConstructProof(util.Log2Ceil(uint64(amount)), 1)
		assert.Nil(t, errProof)
		assert.True(t, proof.ValidateSubtree(&tree.nodes[util.Log2Ceil(uint64(amount))][1], tree.Root()))
		encoded, errEnc := proof.Serialize()
		assert.Nil(t, errEnc)
		assert.NotNil(t, encoded)
		decoded, errDec := DeserializeProof(encoded)
		assert.Nil(t, errDec)
		assert.NotNil(t, decoded)
		assert.True(t, proof.ValidateSubtree(&tree.nodes[util.Log2Ceil(uint64(amount))][1], tree.Root()))
		assert.True(t, reflect.DeepEqual(proof, decoded))
	}
}

func TestNegativeValidateLeaf(t *testing.T) {
	testAmounts := []uint64{68, 511, 512, 513, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		// Construct a proof of a leaf node
		proof, err := tree.ConstructProof(tree.Depth()-1, 4)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateLeaf(getLeaf(t, 4), tree.Root()))
		for currentLvl := 0; currentLvl < tree.Depth()-1; currentLvl++ {
			for i := 0; i < digestBytes; i++ {
				// Corrupt a bit in a node
				// Note that modifying the most significant bits of the last byte will still result in failure even tough those bits should never be set
				proof.Path()[currentLvl].Data[i] ^= 0b10000000
				assert.False(t, proof.ValidateLeaf(getLeaf(t, 4), tree.Root()))
				// Reset the proof
				proof.Path()[currentLvl].Data[i] ^= 0b10000000
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
			assert.Nil(t, err)
			assert.True(t, proof.ValidateSubtree(&tree.nodes[lvl][0], tree.Root()))

			// Test the largest node in the level
			proof, err = tree.ConstructProof(lvl, uint64(len(tree.nodes[lvl])-1))
			assert.Nil(t, err)
			assert.True(t, proof.ValidateSubtree(&tree.nodes[lvl][len(tree.nodes[lvl])-1], tree.Root()))

			// Test a node in the middle of the level
			proof, err = tree.ConstructProof(lvl, uint64(len(tree.nodes[lvl])/3))
			assert.Nil(t, err)
			assert.True(t, proof.ValidateSubtree(&tree.nodes[lvl][len(tree.nodes[lvl])/3], tree.Root()))
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
			proof.Path()[currentLvl/3].Data[0] ^= 0b10000000
			assert.False(t, proof.ValidateSubtree(&tree.nodes[currentLvl][idx], tree.Root()))
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
	assert.Nil(t, err)
	encoded, err := proof.Serialize()
	assert.Nil(t, err)
	// Incorrect size of proof
	_, errDec := DeserializeProof(encoded[:2*BytesInInt+1])
	assert.Error(t, errDec)
}

func TestNegativeSerializationProofZeroLevel(t *testing.T) {
	tree := getTree(t, 345)
	proof, err := tree.ConstructProof(5, 12)
	assert.Nil(t, err)
	encoded, err := proof.Serialize()
	assert.Nil(t, err)
	// Set level to 0
	for i := 0; i < BytesInInt; i++ {
		encoded[i] = 0b00000000
	}
	_, errDec := DeserializeProof(encoded)
	assert.Error(t, errDec)
}

func TestNegativeSerializationProofNegativeIndex(t *testing.T) {
	tree := getTree(t, 345)
	proof, err := tree.ConstructProof(5, 12)
	assert.Nil(t, err)
	encoded, err := proof.Serialize()
	assert.Nil(t, err)
	// Set level to MaxUint
	for i := 0; i < 2*BytesInInt; i++ {
		encoded[i] = 0xFF
	}
	_, errDec := DeserializeProof(encoded)
	assert.Error(t, errDec)
}
