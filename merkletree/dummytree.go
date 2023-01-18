package merkletree

import "github.com/filecoin-project/go-data-segment/fr32"

type dummyData struct {
	leafs     []Node
	root      *Node
	leafCount int
	depth     int
	valid     bool
}

func NewDummyTree(leafs []Node, root *Node, leafCount int, depth int, valid bool) MerkleTree {
	return dummyData{
		leafs:     leafs,
		root:      root,
		leafCount: leafCount,
		depth:     depth,
		valid:     valid,
	}
}

func (d dummyData) Depth() int {
	return d.depth
}

func (d dummyData) LeafCount() int {
	return d.leafCount
}

func (d dummyData) Root() *Node {
	return d.root
}

func (d dummyData) Leafs() []Node {
	return d.leafs
}

func (d dummyData) Node(_ int, _ int) *Node {
	return &Node{}
}

func (d dummyData) ConstructProof(lvl int, idx int) (MerkleProof, error) {
	return DummyProof{
		expectedRoot: d.Root(),
		path:         make([]Node, d.Depth()-1),
		lvl:          lvl,
		idx:          idx,
	}, nil
}

func (d dummyData) ConstructBatchedProof(_ int, _ int, _ int, _ int) (BatchedMerkleProof, error) {
	panic("not implemented")
}

func (d dummyData) ValidateFromLeafs(_ [][]byte) bool {
	return d.valid
}

func (d dummyData) Validate() bool {
	return d.valid
}

func (d dummyData) Serialize() ([]byte, error) {
	return make([]byte, 2*d.LeafCount()*fr32.BytesNeeded), nil
}
