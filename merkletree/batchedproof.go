//go:build no

package merkletree

import (
	"github.com/filecoin-project/go-data-segment/util"
	xerrors "golang.org/x/xerrors"
)

// BatchedProofData represents a Merkle proof of a sequence of leafs
type BatchedProofData interface {
	// LeftProof returns the underlying, full, proof of the left-most element proven in the batch
	LeftProof() ProofData
	// RightProof returns the underlying, full, proof of the right-most element proven in the batch
	RightProof() ProofData
	// ValidateSequence ensures the correctness of the proof of a sequence of subtrees against the root of a Merkle tree
	ValidateSequence(firstSubtree *Node, secondSubtree *Node, root *Node) bool
	// ValidateLeafs ensures the correctness of the proof of a sequence of leafs against a Merkle tree.
	// startIdx indicates the index in the tree of the left-most leaf contained in the sequence leafs
	ValidateLeafs(leafs [][]byte, startIdx int, tree MerkleTree) bool
}

type BatchedProofFactory func() BatchedProofData

type batchedProofData struct {
	// leftPath contains the path needed to verify the left-most node only
	leftPath []Node
	// rightPath contains the path needed to verify the right-most node only
	rightPath []Node
	// commonPath contains the path needed to verify everything between the left-most and right-most nodes
	commonPath []Node
	// leftLvl indicates the level in the Merkle tree where the left-most node is located. Root has level 0
	leftLvl int
	// leftIdx indicates the index within leftLvl where the left-most node whose membership to prove is located.
	// Indexing starts at 0
	leftIdx uint64
	// rightLvl indicates the level in the Merkle tree where the right-most node is located. Root has level 0
	rightLvl int
	// rightIdx indicates the index within rightLvl where the right-most node whose membership to prove is located.
	rightIdx uint64
}

func (b batchedProofData) LeftProof() ProofData {
	return b.getSubproof(b.leftPath, b.leftLvl, b.leftIdx)
}

func (b batchedProofData) RightProof() ProofData {
	return b.getSubproof(b.rightPath, b.rightLvl, b.rightIdx)
}

func CreateBatchedProof(leftProof ProofData, rightProof MerkleProof) BatchedMerkleProof {
	// Find common index by starting from the top of the tree and see where the proof-path diverge
	minLength := util.Min(len(leftProof.Path()), len(rightProof.Path()))
	var ctr int
	for ctr = 0; ctr < minLength; ctr++ {
		if leftProof.Path()[ctr] != rightProof.Path()[ctr] {
			break
		}
	}
	leftPath := leftProof.Path()[ctr:]
	rightPath := rightProof.Path()[ctr:]
	commonPath := rightProof.Path()[:ctr]
	return batchedProofData{leftPath: leftPath, rightPath: rightPath, commonPath: commonPath,
		leftIdx: leftProof.Index(), rightIdx: rightProof.Index()}
}

func (b batchedProofData) ValidateSequence(leftSubtree *Node, rightSubtree *Node, root *Node) bool {
	// Validate the full subtree. This could approach could be optimized a bit
	if err := b.getSubproof(b.leftPath, b.leftLvl, b.leftIdx).
		ValidateSubtree(leftSubtree, root); err != nil {
		return false
	}
	if err := b.getSubproof(b.rightPath, b.rightLvl, b.rightIdx).
		ValidateSubtree(rightSubtree, root); err != nil {
		return false
	}
	return true
}

func (b batchedProofData) getSubproof(subPath []Node, lvl int, idx uint64) ProofData {
	// Reconstruct the full path
	fullPath := make([]Node, len(b.commonPath)+len(subPath))
	copy(fullPath, b.commonPath)
	copy(fullPath[len(b.commonPath):], subPath)
	return ProofData{path: fullPath, index: idx}
}

func (b batchedProofData) ValidateLeafs(leafs [][]byte, startIdx int, tree MerkleTree) bool {
	hashedLeafs := make([]Node, len(leafs))
	for i, leaf := range leafs {
		hashedLeafs[i] = *TruncatedHash(leaf)
	}
	// Check that each hashed leaf in the tree matches the input
	for i, hashedLeaf := range hashedLeafs {
		if hashedLeaf != tree.Leafs()[startIdx+i] {
			return false
		}
	}
	// Also check the batched proof from the edges of the leafs
	return b.ValidateSequence(&hashedLeafs[0], &hashedLeafs[len(hashedLeafs)-1], tree.Root())
}

// ConstructBatchedProof constructs a proof that a sequence of leafs are contained in the tree. Either through a subtree or a (hashed) leaf.
// The proof contains everything captured by the node in leftLvl level at index leftIdx up to and INCLUDING everything
// contained by the node in rightLvl level and rightIdx index.
// The root is in level 0 and the left-most node in a given level is indexed 0.
func (d TreeData) ConstructBatchedProof(leftLvl int, leftIdx uint64, rightLvl int, rightIdx uint64) (BatchedProofData, error) {
	if leftLvl < 1 || leftLvl >= d.Depth() || rightLvl < 1 || rightLvl >= d.Depth() {
		return batchedProofData{}, xerrors.New("a level is either below 1 or bigger than the tree supports")
	}
	// Construct individual proofs
	leftProof, err := d.ConstructProof(leftLvl, leftIdx)
	if err != nil {
		return batchedProofData{}, err
	}
	rightProof, err := d.ConstructProof(rightLvl, rightIdx)
	if err != nil {
		return batchedProofData{}, err
	}
	return CreateBatchedProof(leftProof, rightProof), nil
}
