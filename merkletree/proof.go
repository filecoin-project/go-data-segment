package merkletree

type MerkleProof interface {
	// Path returns the nodes in the proof, starting level 1 (the children of the root)
	Path() []Node
	// Level returns the level in the tree of the node in the tree which the proof validates.
	// The root node is at level 0.
	Level() int
	// Index returns the index of the node which the proof validates
	// The left-most node in a given level is 0
	Index() int
	// ValidateLeaf ensures the correctness of the proof of a leaf against the root of a Merkle tree
	ValidateLeaf(leafs []byte, root *Node) bool
	// ValidateSubtree ensures the correctness of the proof of a subtree against the root of a Merkle tree
	ValidateSubtree(subtree *Node, root *Node) bool
}

type ProofData struct {
	path []Node
	// lvl indicates the level in the Merkle tree where root has level 0
	lvl int
	// idx indicates the index within the level where the element whose membership to prove is located
	// Leftmost node is index 0
	idx int
}

func (d ProofData) Path() []Node {
	return d.path
}

func (d ProofData) Level() int {
	return d.lvl
}

func (d ProofData) Index() int {
	return d.idx
}

func (d ProofData) ValidateLeaf(data []byte, root *Node) bool {
	leaf := truncatedHash(data)
	return d.ValidateSubtree(leaf, root)
}

func (d ProofData) ValidateSubtree(subtree *Node, root *Node) bool {
	currentNode := subtree
	currentIdx := d.idx
	var parent *Node
	for currentLvl := d.lvl; currentLvl >= 1; currentLvl-- {
		sibIdx := getSiblingIdx(currentIdx)
		sibling := d.path[currentLvl-1]
		// If the node is all-0 then it means it does not exist
		// It is fine to assume this "magic" array since all nodes will be hash digests and so the all-0 string
		// will only happen with negligible probability
		if sibling.data == [digestBytes]byte{} {
			// In case the node does not exist, the only child will be hashed
			parent = truncatedHash(currentNode.data[:])
		} else {
			// If the sibling is "right" then we must hash currentNode first
			if sibIdx%2 == 1 {
				parent = computeNode(currentNode, &sibling)
			} else {
				parent = computeNode(&sibling, currentNode)
			}
		}
		currentNode = parent
		currentIdx = currentIdx / 2
	}
	// Validate the root against the tree
	if parent.data != root.data {
		return false
	}
	return true
}
