package merkletree

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// PUBLIC METHOD TESTS
func TestGettersSunshine(t *testing.T) {
	tree := getTree(t, 42)
	left, errLeft := tree.ConstructProof(2, 2)
	assert.Nil(t, errLeft)
	right, errRight := tree.ConstructProof(1, 1)
	assert.Nil(t, errRight)
	proof := CreateBatchedProof(left, right)
	assert.True(t, proof.ValidateSequence(&tree.(data).nodes[2][2], &tree.(data).nodes[1][1], tree.Root()))
	assert.True(t, proof.LeftProof().ValidateSubtree(&tree.(data).nodes[2][2], tree.Root()))
	assert.True(t, proof.RightProof().ValidateSubtree(&tree.(data).nodes[1][1], tree.Root()))
}

func TestGettersEmptyProof(t *testing.T) {
	proof := batchedProofData{}
	assert.NotNil(t, proof)
	assert.NotNil(t, proof.LeftProof())
	assert.NotNil(t, proof.RightProof())
}

func TestValidateSequence(t *testing.T) {
	testAmounts := []int{130, 255, 256, 257, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		// Construct a proof of a sequence of hashed leafs
		// Small amount
		proof, err := tree.ConstructBatchedProof(tree.Depth()-1, 3, tree.Depth()-1, 4)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(truncatedHash(getLeaf(t, 3)), truncatedHash(getLeaf(t, 4)), tree.Root()))

		// Large amount
		proof, err = tree.ConstructBatchedProof(tree.Depth()-1, 10, tree.Depth()-2, amount/3)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(truncatedHash(getLeaf(t, 10)), &tree.(data).nodes[tree.Depth()-2][amount/3], tree.Root()))

		// Right-most subtree
		proof, err = tree.ConstructBatchedProof(tree.Depth()-3, 0, tree.Depth()-1, amount-1)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(&tree.(data).nodes[tree.Depth()-3][0], truncatedHash(getLeaf(t, amount-1)), tree.Root()))

		// Subtree
		proof, err = tree.ConstructBatchedProof(tree.Depth()-3, 5, tree.Depth()-2, 1)
		assert.Nil(t, err)
		assert.True(t, proof.ValidateSequence(&tree.(data).nodes[tree.Depth()-3][5], &tree.(data).nodes[tree.Depth()-2][1], tree.Root()))
	}
}

// NEGATIVE TESTING
func TestNegativeValidateSequence(t *testing.T) {
	testAmounts := []int{130, 255, 256, 257, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		// Construct a proof of a leaf node
		proof, err := tree.ConstructBatchedProof(tree.Depth()-2, 9, tree.Depth()-2, 31)
		assert.Nil(t, err)
		for currentLvl := 0; currentLvl < 3; currentLvl++ {
			for i := 0; i < digestBytes; i++ {
				// Corrupt a bit in a node
				// Note that modifying the most significant bits of the last byte will still result in failure even tough those bits should never be set
				proof.(batchedProofData).leftPath[currentLvl].data[i] ^= 0b10000000
				assert.False(t, proof.ValidateSequence(&tree.(data).nodes[tree.Depth()-2][9], &tree.(data).nodes[tree.Depth()-2][31], tree.Root()))
				// Revert the modification of the left proof and try the right proof
				proof.(batchedProofData).leftPath[currentLvl].data[i] ^= 0b10000000

				assert.True(t, proof.ValidateSequence(&tree.(data).nodes[tree.Depth()-2][9], &tree.(data).nodes[tree.Depth()-2][31], tree.Root()))
				proof.(batchedProofData).rightPath[currentLvl].data[i] ^= 0b10000000
				assert.False(t, proof.ValidateSequence(&tree.(data).nodes[tree.Depth()-2][9], &tree.(data).nodes[tree.Depth()-2][31], tree.Root()))
				// Reset the right proof
				proof.(batchedProofData).rightPath[currentLvl].data[i] ^= 0b10000000
			}
		}
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

// NEGATIVE TESTING
func TestNegativeValidateLeafs(t *testing.T) {
	testAmounts := []int{68, 511, 512, 513, 1000000}
	for _, amount := range testAmounts {
		tree := getTree(t, amount)
		// Construct a proof of a leaf node
		proof, err := tree.ConstructBatchedProof(tree.Depth()-1, 16, tree.Depth()-1, 22)
		assert.Nil(t, err)
		for currentLvl := 0; currentLvl < 3; currentLvl++ {
			for i := 0; i < digestBytes; i++ {
				// Corrupt a bit in a node
				// Note that modifying the most significant bits of the last byte will still result in failure even tough those bits should never be set
				proof.(batchedProofData).leftPath[currentLvl].data[i] ^= 0b10000000
				assert.False(t, proof.ValidateLeafs(getLeafs(t, 16, 22-16+1), 16, tree))
				// Revert the modification of the left proof and try the right proof
				proof.(batchedProofData).leftPath[currentLvl].data[i] ^= 0b10000000

				assert.True(t, proof.ValidateLeafs(getLeafs(t, 16, 22-16+1), 16, tree))
				proof.(batchedProofData).rightPath[currentLvl].data[i] ^= 0b10000000
				assert.False(t, proof.ValidateLeafs(getLeafs(t, 16, 22-16+1), 16, tree))
				// Reset the right proof
				proof.(batchedProofData).rightPath[currentLvl].data[i] ^= 0b10000000
			}
		}
	}
}

func TestNegativeErrorInLeaf(t *testing.T) {
	tree := getTree(t, 234)
	proof, err := tree.ConstructBatchedProof(tree.Depth()-1, 53, tree.Depth()-1, 56)
	assert.Nil(t, err)
	assert.True(t, proof.ValidateLeafs(getLeafs(t, 53, 56-53+1), 53, tree))
	// Modify a leaf
	tree.(data).nodes[tree.Depth()-1][56].data[0] ^= 0b00100000
	assert.False(t, proof.ValidateLeafs(getLeafs(t, 53, 56-53+1), 53, tree))
}

func TestNegativeBadLevel(t *testing.T) {
	tree := getTree(t, 12)
	_, err := tree.ConstructBatchedProof(0, 0, tree.Depth()-1, 1)
	assert.NotNil(t, err)
	_, err = tree.ConstructBatchedProof(tree.Depth()-1, 0, tree.Depth(), 1)
	assert.NotNil(t, err)
	_, err = tree.ConstructBatchedProof(tree.Depth(), 0, tree.Depth()-1, 1)
	assert.NotNil(t, err)
	_, err = tree.ConstructBatchedProof(tree.Depth()-1, 0, 0, 1)
	assert.NotNil(t, err)
}

func TestNegativeBadIndex(t *testing.T) {
	tree := getTree(t, 12)
	_, err := tree.ConstructBatchedProof(tree.Depth()-1, -1, tree.Depth()-1, 1)
	assert.NotNil(t, err)
	_, err = tree.ConstructBatchedProof(tree.Depth()-1, 0, tree.Depth()-1, -1)
	assert.NotNil(t, err)
	_, err = tree.ConstructBatchedProof(tree.Depth()-1, 0, tree.Depth()-1, 10000)
	assert.NotNil(t, err)
	_, err = tree.ConstructBatchedProof(tree.Depth()-1, 10000, tree.Depth()-1, 1)
	assert.NotNil(t, err)
}
