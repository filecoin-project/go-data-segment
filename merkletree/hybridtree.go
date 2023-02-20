package merkletree

import (
	"github.com/filecoin-project/go-data-segment/util"
	"golang.org/x/xerrors"
)

type Hybrid struct {
	// The sparse array contains the data of the tree
	// Levels of the tree are counted from the leaf layer, leaf leater is layer 0.
	// Where the leaf layer lands depends on the log2Leafs value.
	// The root node of a the tree is stored at position [1].
	// The leaf data is stored at [2^(log2Leafs):2^(log2Leafs+1)]]
	// Level N is at: [2^(log2Leafs-level):2^(log2Leafs-level+1)]
	data      SparseArray[Node]
	log2Leafs int
}

func NewHybrid(log2Leafs int) (Hybrid, error) {
	if log2Leafs > 63 {
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
		panic(err)
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
	return 1<<(ht.log2Leafs-level) + uint64(index)
}

func (ht *Hybrid) SetNode(level int, idx uint64, n *Node) error {
	if err := ht.validateLevelIndex(level, idx); err != nil {
		return xerrors.Errorf("in SetNode: %w", err)
	}
	// verify that subtrees this node are empty
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
			return xerrors.Errorf("left subtree not empty")
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

type DealInfo struct {
	Comm Node
	Size uint64

	Placed bool
	Level  int
	Index  uint64
}

// ComputeDealPlacement takes in DealInfos with Comm and Size,
// computes their placement in the tree and modifies DealInfos with Level and Index information.
// Reeturns number of bytes required and any errors
func ComputeDealPlacement(dealInfos []DealInfo) (uint64, error) {
	offset := uint64(0)
	for i := range dealInfos {
		di := &dealInfos[i]
		sizeInNodes := uint64(di.Size) / NodeSize
		di.Placed = true
		di.Level = util.Log2Ceil(sizeInNodes)               // level is log2(sizeInNodes)
		di.Index = (offset + sizeInNodes - 1) / sizeInNodes // idx is ceil(offset/sizeInNodes)
		offset = (di.Index + 1) * sizeInNodes               // select the next index at ni.lvl and go back to nodewise
	}
	return offset, nil
}

// PlaceDeals takes DealInfos and places them within the hybrid tree.
func PlaceDeals(ht *Hybrid, dealInfos []DealInfo) error {
	for i, di := range dealInfos {
		if !di.Placed {
			return xerrors.Errorf("deal at index %d is not placed", i)
		}

		err := ht.SetNode(di.Level, di.Index, &di.Comm)
		if err != nil {
			return xerrors.Errorf("setting node for deal at index %d failed: %w", i, err)
		}
	}
	return nil
}

// 256 nodes per block, resulting in 8KiB blocks
const SparseBlockSize = 1 << 8

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

// Set returns the old value
func (sa *SparseArray[T]) Set(index uint64, val *T) T {
	if sa.subs == nil {
		sa.subs = make(map[uint64][]T)
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
