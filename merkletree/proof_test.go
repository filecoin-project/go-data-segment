package merkletree

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// PUBLIC METHODS
func TestValidateLeafSunshine(t *testing.T) {
	testAmounts := []int{130, 255, 256, 257, 1000000}
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

func TestNegativeValidateLeaf(t *testing.T) {
	testAmounts := []int{68, 511, 512, 513, 1000000}
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
				proof.Path()[currentLvl].data[i] ^= 0b10000000
				assert.False(t, proof.ValidateLeaf(getLeaf(t, 4), tree.Root()))
				// Reset the proof
				proof.Path()[currentLvl].data[i] ^= 0b10000000
			}
		}
	}
}

func TestValidateProofSubtree(t *testing.T) {
	testAmounts := []int{1300, 65535, 65536, 65537}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		for lvl := 1; lvl < tree.Depth(); lvl++ {
			// Test the smallest node in the level
			proof, err := tree.ConstructProof(lvl, 0)
			assert.Nil(t, err)
			assert.True(t, proof.ValidateSubtree(&tree.(data).nodes[lvl][0], tree.Root()))

			// Test the largest node in the level
			proof, err = tree.ConstructProof(lvl, len(tree.(data).nodes[lvl])-1)
			assert.Nil(t, err)
			assert.True(t, proof.ValidateSubtree(&tree.(data).nodes[lvl][len(tree.(data).nodes[lvl])-1], tree.Root()))

			// Test a node in the middle of the level
			proof, err = tree.ConstructProof(lvl, len(tree.(data).nodes[lvl])/3)
			assert.Nil(t, err)
			assert.True(t, proof.ValidateSubtree(&tree.(data).nodes[lvl][len(tree.(data).nodes[lvl])/3], tree.Root()))
		}
	}
}

func TestNegativeValidateSubtree(t *testing.T) {
	testAmounts := []int{68, 511, 512, 513, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		for currentLvl := 1; currentLvl < tree.Depth()-1; currentLvl++ {
			// Construct a proof of the second to most right node
			idx := len(tree.(data).nodes[currentLvl]) - 2
			proof, err := tree.ConstructProof(currentLvl, idx)
			assert.Nil(t, err)
			// Corrupt a bit in a node
			proof.Path()[currentLvl/3].data[0] ^= 0b10000000
			assert.False(t, proof.ValidateSubtree(&tree.(data).nodes[currentLvl][idx], tree.Root()))
		}
	}
}
