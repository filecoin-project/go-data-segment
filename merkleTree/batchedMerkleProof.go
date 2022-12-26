package merkleTree

type BatchedMerkleProof interface {
	// ValidateSequence ensures the correctness of the proof of a sequence of subtrees against the root of a Merkle tree
	ValidateSequence(firstSubtree *Node, secondSubtree *Node, root *Node) bool
	// ValidateLeafs ensures the correctness of the proof of a sequence of subtrees against the root of a Merkle tree
	ValidateLeafs(leafs [][]byte, root *Node) bool
}

type BatchedProofFactory func() BatchedMerkleProof

type BatchedProofData struct {
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
	leftIdx int
	// rightLvl indicates the level in the Merkle tree where the right-most node is located. Root has level 0
	rightLvl int
	// rightIdx indicates the index within rightLvl where the right-most node whose membership to prove is located.
	rightIdx int
}

func CreateEmptyBatchedProof() BatchedMerkleProof {
	return BatchedProofData{}
}

func CreateBatchedProof(leftProof BatchedMerkleProof, rightProof BatchedMerkleProof) BatchedMerkleProof {
	return BatchedProofData{}
}

func (b BatchedProofData) ValidateSequence(leftSubtree *Node, rightSubtree *Node, root *Node) bool {
	// Reconstruct the full path
	fullPathLeft := make([]Node, len(b.commonPath)+len(b.leftPath))
	fullPathRight := make([]Node, len(b.commonPath)+len(b.rightPath))
	copy(fullPathLeft, b.commonPath)
	copy(fullPathLeft[len(b.commonPath):], b.leftPath)
	copy(fullPathRight, b.commonPath)
	copy(fullPathRight[len(b.commonPath):], b.rightPath)
	leftProof := ProofData{path: fullPathLeft, lvl: b.leftLvl, idx: b.leftIdx}
	rightProof := ProofData{path: fullPathRight, lvl: b.rightLvl, idx: b.rightIdx}
	if !leftProof.ValidateSubtree(leftSubtree, root) {
		return false
	}
	if !rightProof.ValidateSubtree(rightSubtree, root) {
		return false
	}
	return true
}

func (b BatchedProofData) ValidateLeafs(leafs [][]byte, root *Node) bool {
	//TODO implement me
	panic("implement me")
}
