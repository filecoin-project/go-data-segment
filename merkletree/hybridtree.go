package merkletree

import (
	"golang.org/x/xerrors"
)

type Hybrid struct {
	// The sparse array contains the data of the tree
	// Levels of the tree are counted from the leaf layer, leaf leater is layer 0.
	// Where the leaf layer lands depends on the log2Leafs value.
	// The root node of a the tree is stored at position [1].
	log2Leafs int
	data      SparseArray[Node]
}

// Location represents a location in the MerkleTree
// Level is counted from the leaf layer, with 0 being leaf layer.
type Location struct {
	Level int
	Index uint64
}

func (l Location) LeafIndex() uint64 {
	return l.Index << l.Level
}

func NewHybrid(log2Leafs int) (Hybrid, error) {
	if log2Leafs > 60 {
		return Hybrid{}, xerrors.Errorf("too many leafs: 2^%d", log2Leafs)
	}
	if log2Leafs < 0 {
		return Hybrid{}, xerrors.Errorf("cannot have negative log2Leafs")
	}
	return Hybrid{log2Leafs: log2Leafs}, nil
}

func (ht Hybrid) MaxLevel() int {
	return ht.log2Leafs
}

func (ht Hybrid) Root() Node {
	n, err := ht.GetNode(ht.MaxLevel(), 0)
	if err != nil {
		panic("unexpected: " + err.Error())
	}
	return n
}

// CollectProof collects a proof from the specified node to the root of the tree
func (ht Hybrid) CollectProof(level int, idx uint64) (ProofData, error) {
	if err := ht.validateLevelIndex(level, idx); err != nil {
		return ProofData{}, xerrors.Errorf("CollectProof input check: %w", err)
	}

	var res ProofData
	res.Index = idx
	for l := level; l < ht.MaxLevel(); l++ {
		n, err := ht.GetNode(l, idx^1) // idx^1 is the sybling index
		if err != nil {
			return ProofData{}, xerrors.Errorf("collecting proof: %w", err)
		}
		idx /= 2
		res.Path = append(res.Path, n)
	}

	return res, nil
}

func (ht Hybrid) GetNode(level int, idx uint64) (Node, error) {
	n, err := ht.getNodeRaw(level, idx)
	if err != nil {
		return Node{}, xerrors.Errorf("getting node: %w", err)
	}

	if n.IsZero() {
		return ZeroCommitmentForLevel(level), nil
	}
	return n, nil
}

func (ht Hybrid) getNodeRaw(level int, idx uint64) (Node, error) {
	if err := ht.validateLevelIndex(level, idx); err != nil {
		return Node{}, xerrors.Errorf("in getNodeRaw: %w", err)
	}
	return ht.data.Get(ht.idxFor(level, idx)), nil
}
func (ht Hybrid) validateLevelIndex(level int, idx uint64) error {
	if level < 0 {
		return xerrors.Errorf("level is negative")
	}
	if level > ht.log2Leafs {
		return xerrors.Errorf("level too high: %d >= %d", level, ht.log2Leafs)
	}
	if idx > (1<<(ht.log2Leafs-level))-1 {
		return xerrors.Errorf("index too large for level: idx %d, level %d", idx, level)
	}
	return nil
}

func (ht Hybrid) idxFor(level int, index uint64) uint64 {
	// Hybrid Tree stores the MT as smaller trees in chunks dictated by SparseBlockSize
	// For example with SparseBlockLog2Size of 8, each SparseBlock will store a single
	// 8 deep tree. These threes are then stored one after breath-wise.
	depth := ht.log2Leafs - level
	const SubtreeDepth = SparseBlockLog2Size

	depthOfSubtree := depth / SubtreeDepth // how deep is the subtree counted by subtree
	depthInSubtree := depth % SubtreeDepth
	widthOfSubtreeAtDepth := uint64(1) << depthInSubtree // how wide is the subtree for given depth
	indexOfSubtree := index / widthOfSubtreeAtDepth      // what is the index of the subtree we should write to

	indexInSubtree := widthOfSubtreeAtDepth + index%widthOfSubtreeAtDepth // what is the index in subtree

	// offsetOfSubtreeLayer = sum(SparseBlockSize^N, {N, 0, depth}) - 1
	offsetOfSubtreeLayer := (uint64(1)<<((depthOfSubtree+1)*SparseBlockLog2Size)-1)/(SparseBlockSize-1) - 1
	offsetOfSubtree := offsetOfSubtreeLayer + SparseBlockSize*indexOfSubtree

	res := offsetOfSubtree + indexInSubtree
	return res
}

func (ht *Hybrid) SetNode(level int, idx uint64, n *Node) error {
	if err := ht.validateLevelIndex(level, idx); err != nil {
		return xerrors.Errorf("in SetNode: %w", err)
	}
	// verify that subtrees of this node are empty
	if level > 0 {
		left, err := ht.getNodeRaw(level-1, 2*idx)
		if err != nil {
			return xerrors.Errorf("getting subtree for validation: %w", err)
		}
		if !left.IsZero() {
			return xerrors.Errorf("left subtree not empty")
		}
		right, err := ht.getNodeRaw(level-1, 2*idx+1)
		if err != nil {
			return xerrors.Errorf("getting subtree for validation: %w", err)
		}
		if !right.IsZero() {
			return xerrors.Errorf("right subtree not empty")
		}
	}

	ht.data.Set(ht.idxFor(level, idx), n)

	curIdx := idx
	for i := level; i < ht.MaxLevel(); i++ {
		nextIndex := curIdx >> 1

		left, err := ht.getNodeRaw(i, curIdx&^1) // clear the lowest bit of index for left node
		if err != nil {
			return xerrors.Errorf("getting left node during update: %w", err)
		}

		right, err := ht.getNodeRaw(i, curIdx|1) // set the lowest bit of index for right now
		if err != nil {
			return xerrors.Errorf("getting right node during update: %w", err)
		}

		if left.IsZero() && right.IsZero() {
			ht.data.Set(ht.idxFor(i+1, nextIndex), &Node{})
			curIdx = nextIndex
			continue
		}

		zC := ZeroCommitmentForLevel(i)
		if left.IsZero() {
			left = zC
		}
		if right.IsZero() {
			right = zC
		}

		n := computeNode(&left, &right)
		ht.data.Set(ht.idxFor(i+1, nextIndex), n)
		curIdx = nextIndex
	}

	return nil
}

// CommAndLoc represents Commitment and Location
type CommAndLoc struct {
	Comm Node
	Loc  Location
}

// BatchSet can be used for optimisation if necessary
// Current algorith is O(M*log2(N)) where M=len(vals) and N=#leafs
// There exists an optimization of applying all Set operations at the same time
// avoiding the repeated updates to the same nodes.
// This results in complexity always better than O(M*log2(N)),
// O(M+log2(N)) in the best case scenario, with the worse case of O(N).
func (ht *Hybrid) BatchSet(vals []CommAndLoc) error {
	for i, v := range vals {
		if err := ht.SetNode(v.Loc.Level, v.Loc.Index, &v.Comm); err != nil {
			return xerrors.Errorf("failed setting, index in batch %d, val: %v: %w", i, v, err)
		}
	}
	return nil
}

// 256 nodes per block, resulting in 8KiB blocks
const SparseBlockLog2Size = 8 // bench and tune if it is an issue
const SparseBlockSize = 1 << SparseBlockLog2Size

type SparseArray[T any] struct {
	subs map[uint64][]T
}

func (sa SparseArray[T]) Get(index uint64) T {
	var res T
	if sa.subs == nil {
		return res
	}
	sub, ok := sa.subs[index/SparseBlockSize]
	if !ok {
		return res
	}
	res = sub[index%SparseBlockSize]

	return res
}

func (sa *SparseArray[T]) initSubs() {
	sa.subs = make(map[uint64][]T)
}

// Set returns the old value
func (sa *SparseArray[T]) Set(index uint64, val *T) T {
	if sa.subs == nil {
		sa.initSubs()
	}
	sub, ok := sa.subs[index/SparseBlockSize]
	if !ok {
		sub = make([]T, SparseBlockSize)
		sa.subs[index/SparseBlockSize] = sub
	}
	res := sub[index%SparseBlockSize]

	sub[index%SparseBlockSize] = *val
	return res
}

func (sa *SparseArray[T]) GetSliceRef(index uint64, length int) ([]T, error) {
	if index/SparseBlockSize != (index+uint64(length)-1)/SparseBlockSize {
		return nil, xerrors.Errorf("requested slice does not align with one sparse block")
	}
	if sa.subs == nil {
		sa.subs = make(map[uint64][]T)
	}
	sub, ok := sa.subs[index/SparseBlockSize]
	if !ok {
		sub = make([]T, SparseBlockSize)
		sa.subs[index/SparseBlockSize] = sub
	}

	return sub[index%SparseBlockSize : (index+uint64(length))%SparseBlockSize], nil
}
