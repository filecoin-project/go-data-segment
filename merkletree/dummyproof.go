package merkletree

type DummyProof struct {
	expectedRoot *Node
	path         []Node
	// lvl indicates the level in the Merkle tree where root has level 0
	lvl int
	// idx indicates the index within the level where the element whose membership to prove is located
	// Leftmost node is index 0
	idx int
}

func NewDummyProof(lvl int, idx int, root *Node) MerkleProof {
	var proof DummyProof
	proof.path = make([]Node, lvl+1)
	proof.expectedRoot = root
	proof.lvl = lvl
	proof.idx = idx
	return proof
}

func (d DummyProof) Serialize() ([]byte, error) {
	proof := proofData{
		path: d.Path(),
		lvl:  d.Level(),
		idx:  d.Index(),
	}
	return proof.Serialize()
	//return make([]byte, fr32.BytesNeeded*len(d.Path())+BytesInInt*2), nil
}

// Path returns the nodes in the path of the proof.
// The first node, is in level 1. I.e. the level below the root
func (d DummyProof) Path() []Node {
	return d.path
}

// Level returns the level in the tree which the node this proof validates, is located
func (d DummyProof) Level() int {
	return d.lvl
}

// Index returns the index of the node this proof validates, within the level returned by Level()
func (d DummyProof) Index() int {
	return d.idx
}

// ValidateLeaf validates that the Data given as input is contained in a Merkle tree with a specific root
func (d DummyProof) ValidateLeaf(data []byte, root *Node) bool {
	if *root != *d.expectedRoot {
		return false
	}
	return true
}

// ValidateSubtree validates that a subtree is contained in the in a Merkle tree with a given root
func (d DummyProof) ValidateSubtree(subtree *Node, root *Node) bool {
	if *root != *d.expectedRoot {
		return false
	}
	return true
}
