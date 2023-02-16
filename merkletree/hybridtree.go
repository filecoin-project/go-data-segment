package merkletree

import (
	"golang.org/x/xerrors"
)

type HybridTree struct {
	// The sparse array contains the data of the tree
	// Levels of the tree are counted from the leaf layer, leaf leater is layer 0.
	// Where the leaf layer lands depends on the log2Leafs value.
	// The root node of a the tree is stored at position [1].
	// The leaf data is stored at [2^(log2Leafs):2^(log2Leafs+1)]]
	// Level N is at: [2^(log2Leafs-level):2^(log2Leafs-level)]
	// With non-zero level offset, the tree gets smaller.
	data      SparseArray[Node]
	log2Leafs int
}

func NewHybridTree(log2Leafs int) (HybridTree, error) {
	if log2Leafs > 63 {
		return HybridTree{}, xerrors.Errorf("too many leafs: 2^%d", log2Leafs)
	}
	if log2Leafs < 0 {
		return HybridTree{}, xerrors.Errorf("cannot have negative log2Leafs")
	}
	return HybridTree{log2Leafs: log2Leafs}, nil
}

func (ht HybridTree) validateLevelIndex(level int, idx uint64) error {
	if level > ht.log2Leafs {
		return xerrors.Errorf("level too high: %d >= %d", level, ht.log2Leafs)
	}
	if idx > (1<<(ht.log2Leafs-level))-1 {
		return xerrors.Errorf("index too large for level: idx %d, level %d", idx, level)
	}
	return nil
}

func (ht HybridTree) idxFor(level int, index uint64) uint64 {
	return 1<<(ht.log2Leafs-level) + uint64(index)
}
func (ht HybridTree) MaxLevel() int {
	return ht.log2Leafs
}

func (ht HybridTree) Root() Node {
	n, err := ht.GetNode(ht.MaxLevel(), 0)
	if err != nil {
		panic(err)
	}
	return n
}

func (ht HybridTree) GetNode(level int, idx uint64) (Node, error) {
	n, err := ht.getNodeRaw(level, idx)
	if err != nil {
		return Node{}, xerrors.Errorf("getting node: %w", err)
	}

	if n.IsZero() {
		return ZeroCommitmentForLevel(level), nil
	}
	return n, nil
}

func (ht HybridTree) getNodeRaw(level int, idx uint64) (Node, error) {
	if err := ht.validateLevelIndex(level, idx); err != nil {
		return Node{}, xerrors.Errorf("in getNodeRaw: %w", err)
	}
	return ht.data.Get(ht.idxFor(level, idx)), nil
}

func (ht *HybridTree) SetNode(level int, idx uint64, n *Node) error {
	if err := ht.validateLevelIndex(level, idx); err != nil {
		return xerrors.Errorf("in SetNode: %w", err)
	}
	ht.data.Set(ht.idxFor(level, idx), n)

	curIdx := idx / 2
	for i := level + 1; i <= ht.MaxLevel(); i++ {
		left, err := ht.getNodeRaw(i-1, 2*curIdx)
		if err != nil {
			return xerrors.Errorf("getting left node during update: %w", err)
		}

		right, err := ht.getNodeRaw(i-1, 2*curIdx+1)
		if err != nil {
			return xerrors.Errorf("getting right node during update: %w", err)
		}

		if left.IsZero() && right.IsZero() {
			ht.data.Set(ht.idxFor(i, curIdx), &Node{})
			curIdx = curIdx / 2
			continue
		}

		zC := ZeroCommitmentForLevel(i - 1)
		if left.IsZero() {
			left = zC
		}
		if right.IsZero() {
			right = zC
		}

		n := computeNode(&left, &right)
		ht.data.Set(ht.idxFor(i, curIdx), n)
		curIdx = curIdx / 2
	}

	return nil
}

const SparseBlockSize = 1 << 10

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
