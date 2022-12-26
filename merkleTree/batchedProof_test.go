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
		proof, err = tree.ConstructBatchedProof(tree.Depth()-1, 10, tree.Depth()-2, amount/3)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(truncatedHash(getLeaf(t, 10)), &tree.(TreeData).nodes[tree.Depth()-2][amount/3], tree.GetRoot()))

		// Right-most subtree
		proof, err = tree.ConstructBatchedProof(tree.Depth()-3, 0, tree.Depth()-1, amount-1)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(&tree.(TreeData).nodes[tree.Depth()-3][0], truncatedHash(getLeaf(t, amount-1)), tree.GetRoot()))

		// Subtree
		proof, err = tree.ConstructBatchedProof(tree.Depth()-3, 0, tree.Depth()-2, 1)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(&tree.(TreeData).nodes[tree.Depth()-3][0], &tree.(TreeData).nodes[tree.Depth()-2][1], tree.GetRoot()))
	}
}

func TestValidateLeafSequence(t *testing.T) {
	testAmounts := []int{42, 234, 4564, 4869}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		proof, err := tree.ConstructBatchedProof(tree.Depth()-1, 5, tree.Depth()-1, 10)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateLeafs(getLeafs(t, 5, 10-5+1), 5, tree))

		proof, err = tree.ConstructBatchedProof(tree.Depth()-1, 15, tree.Depth()-1, amount/3+2)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateLeafs(getLeafs(t, 15, amount/3+2-15+1), 15, tree))

		// Check the whole tree
		proof, err = tree.ConstructBatchedProof(tree.Depth()-1, 0, tree.Depth()-1, amount-1)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateLeafs(getLeafs(t, 0, amount), 0, tree))
	}
}
