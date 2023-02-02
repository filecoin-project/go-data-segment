package merkletree

// MerkleProof represents a Merkle proof to a single leaf in a Merkle tree
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

type proofData struct {
	path []Node
	// lvl indicates the level in the Merkle tree where root has level 0
	lvl int
	// idx indicates the index within the level where the element whose membership to prove is located
	// Leftmost node is index 0
	idx int
}

// Path returns the nodes in the path of the proof.
// The first node, is in level 1. I.e. the level below the root
func (d proofData) Path() []Node {
	return d.path
}

// Level returns the level in the tree which the node this proof validates, is located
func (d proofData) Level() int {
	return d.lvl
}

// Index returns the index of the node this proof validates, within the level returned by Level()
func (d proofData) Index() int {
	return d.idx
}

// ValidateLeaf validates that the data given as input is contained in a Merkle tree with a specific root
func (d proofData) ValidateLeaf(data []byte, root *Node) bool {
	leaf := truncatedHash(data)
	return d.ValidateSubtree(leaf, root)
}

// ValidateSubtree validates that a subtree is contained in the in a Merkle tree with a given root
func (d proofData) ValidateSubtree(subtree *Node, root *Node) bool {
	currentNode := subtree
	currentIdx := d.idx
	var parent *Node
	for currentLvl := d.lvl; currentLvl >= 1; currentLvl-- {
		sibIdx := getSiblingIdx(currentIdx)
		sibling := d.path[currentLvl-1]
		// If the sibling is "right" then we must hash currentNode first
		if sibIdx%2 == 1 {
			parent = computeNode(currentNode, &sibling)
		} else {
			parent = computeNode(&sibling, currentNode)
		}
		currentNode = parent
		currentIdx = currentIdx / 2
	}
	// Validate the root against the tree
	return parent.data == root.data
}
