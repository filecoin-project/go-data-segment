package merkleTree

type BatchedMerkleProof interface {
	// ValidateSequence ensures the correctness of the proof of a sequence of subtrees against the root of a Merkle tree
	ValidateSequence(firstSubtree *Node, secondSubtree *Node, root *Node) bool
	// ValidateLeafs ensures the correctness of the proof of a sequence of leafs against a Merkle tree.
	// startIdx indicates the index in the tree of the left-most leaf contained in the sequence leafs
	ValidateLeafs(leafs [][]byte, startIdx int, tree MerkleTree) bool
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

func CreateBatchedProof(leftProof MerkleProof, rightProof MerkleProof) BatchedMerkleProof {
	// Find common index by starting from the top of the tree and see where the proof-path diverge
	minLength := min(len(leftProof.GetPath()), len(rightProof.GetPath()))
	var ctr int
	for ctr = 0; ctr < minLength; ctr++ {
		if leftProof.GetPath()[ctr] != rightProof.GetPath()[ctr] {
			break
		}
	}
	leftPath := leftProof.GetPath()[ctr:]
	rightPath := rightProof.GetPath()[ctr:]
	commonPath := rightProof.GetPath()[:ctr]
	return BatchedProofData{leftPath: leftPath, rightPath: rightPath, commonPath: commonPath, leftLvl: leftProof.GetLevel(),
		leftIdx: leftProof.GetIndex(), rightLvl: rightProof.GetLevel(), rightIdx: rightProof.GetIndex()}
}

func (b BatchedProofData) ValidateSequence(leftSubtree *Node, rightSubtree *Node, root *Node) bool {
	if !b.validatePath(leftSubtree, b.leftPath, b.leftLvl, b.leftIdx, root) {
		return false
	}
	if !b.validatePath(rightSubtree, b.rightPath, b.rightLvl, b.rightIdx, root) {
		return false
	}
	return true
}

func (b BatchedProofData) validatePath(subtree *Node, path []Node, lvl int, idx int, root *Node) bool {
	// Reconstruct the full path
	fullPath := make([]Node, len(b.commonPath)+len(path))
	copy(fullPath, b.commonPath)
	copy(fullPath[len(b.commonPath):], path)
	proof := ProofData{path: fullPath, lvl: lvl, idx: idx}
	// Validate the full subtree. This could approach could be optimized a bit
	if !proof.ValidateSubtree(subtree, root) {
		return false
	}
	return true
}

func (b BatchedProofData) ValidateLeafs(leafs [][]byte, startIdx int, tree MerkleTree) bool {
	hashedLeafs := make([]Node, len(leafs))
	for i, leaf := range leafs {
		hashedLeafs[i] = *truncatedHash(leaf)
	}
	// Check the batched proof from the edges of the leafs
	if !b.ValidateSequence(&hashedLeafs[0], &hashedLeafs[len(hashedLeafs)-1], tree.GetRoot()) {
		return false
	}
	// Also check that each hashed leaf in the tree matches the input
	for i, hashedLeaf := range hashedLeafs {
		if hashedLeaf != tree.GetLeafs()[startIdx+i] {
			return false
		}
	}
	return true
}
