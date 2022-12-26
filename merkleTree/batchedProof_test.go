package merkleTree

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// PUBLIC METHOD TESTS

func TestValidateSequence(t *testing.T) {
	testAmounts := []int{130, 255, 256, 257, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		// Construct a proof of a sequence of hashed leafs
		// Small amount
		proof, err := tree.ConstructBatchedProof(tree.Depth()-1, 3, tree.Depth()-1, 4)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(truncatedHash(getLeaf(t, 3)), truncatedHash(getLeaf(t, 4)), tree.GetRoot()))
		// Large amount
		proof, err = tree.ConstructBatchedProof(tree.Depth()-1, 10, tree.Depth()-1, amount/3)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(truncatedHash(getLeaf(t, 10)), truncatedHash(getLeaf(t, amount/3)), tree.GetRoot()))
		// Entire tree
		proof, err = tree.ConstructBatchedProof(tree.Depth()-1, 0, tree.Depth()-1, amount-1)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(truncatedHash(getLeaf(t, 0)), truncatedHash(getLeaf(t, amount-1)), tree.GetRoot()))
	}
}
