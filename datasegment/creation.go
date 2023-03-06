package datasegment

import (
	"bytes"
	"io"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	abi "github.com/filecoin-project/go-state-types/abi"
	cid "github.com/ipfs/go-cid"
	xerrors "golang.org/x/xerrors"
)

type Aggregate struct {
	DealSize abi.PaddedPieceSize
	Index    IndexData
	Tree     merkletree.Hybrid
}

func NewAggregate(dealSize abi.PaddedPieceSize, subdeals []abi.PieceInfo) (*Aggregate, error) {
	maxEntries := MaxIndexEntriesInDeal(dealSize)
	if uint(len(subdeals)) > maxEntries {
		return nil, xerrors.Errorf("too many subdeals for a %d sized deal: %d > %d",
			dealSize, len(subdeals), maxEntries)
	}
	cl, totalSize, err := ComputeDealPlacement(subdeals)
	_ = cl
	if err != nil {
		return nil, xerrors.Errorf("computing deal placment: %w", err)
	}

	if totalSize+uint64(maxEntries)*EntrySize > uint64(dealSize) {
		return nil, xerrors.Errorf(
			"sub-deals are too large to fit in the index: %d (packed subdeals) + %d (index) > %d (dealSize)",
			totalSize, maxEntries*EntrySize, dealSize)
	}

	ht, err := merkletree.NewHybrid(util.Log2Ceil(uint64(dealSize / merkletree.NodeSize)))
	if err != nil {
		return nil, xerrors.Errorf("failed creating hybrid tree: %w", err)
	}
	err = ht.BatchSet(cl)
	if err != nil {
		return nil, xerrors.Errorf("batch set of deal nodes failed: %w", err)
	}
	index, err := MakeIndexFromCommLoc(cl)
	if err != nil {
		return nil, xerrors.Errorf("failed creating index: %w", err)
	}

	indexStartNodes := indexAreaStart(dealSize) / merkletree.NodeSize
	batch := make([]merkletree.CommAndLoc, 2*len(index.Entries))
	for i, e := range index.Entries {
		ns := e.IntoNodes()
		batch[2*i] = merkletree.CommAndLoc{
			Comm: ns[0],
			Loc:  merkletree.Location{Level: 0, Index: indexStartNodes + 2*uint64(i)},
		}
		batch[2*i+1] = merkletree.CommAndLoc{
			Comm: ns[1],
			Loc:  merkletree.Location{Level: 0, Index: indexStartNodes + 2*uint64(i) + 1},
		}
	}
	err = ht.BatchSet(batch)
	if err != nil {
		return nil, xerrors.Errorf("batch set of index nodes failed: %w", err)
	}

	deal := Aggregate{
		DealSize: dealSize,
		Index:    *index,
		Tree:     ht,
	}

	return &deal, nil
}

// PieceCID returns the PieceCID of the deal containng all subdeals and the index
func (d Aggregate) PieceCID() (cid.Cid, error) {
	n := d.Tree.Root()
	return commcid.PieceCommitmentV1ToCID(n[:])
}

func (d Aggregate) indexLoc() merkletree.Location {
	level := util.Log2Ceil(EntrySize / merkletree.NodeSize * uint64(MaxIndexEntriesInDeal(d.DealSize)))
	index := uint64(1)<<level - 1
	return merkletree.Location{Level: level, Index: index}
}

// IndexPieceCID returns the PieceCID of the index
func (d Aggregate) IndexPieceCID() (cid.Cid, error) {
	l := d.indexLoc()
	n, err := d.Tree.GetNode(l.Level, l.Index)
	if err != nil {
		return cid.Undef, xerrors.Errorf("getting node: %w", err)
	}
	return commcid.PieceCommitmentV1ToCID(n[:])
}

// IndexReader returns a reader for the index containing unpadded bytes of the index
func (d Aggregate) IndexReader() (io.Reader, error) {
	b, err := d.Index.MarshalBinary()
	if err != nil {
		return nil, xerrors.Errorf("marshaling index: %w", err)
	}
	if rem := len(b) % 128; rem != 0 {
		// pad to 128 bytes
		b = append(b, make([]byte, 128-rem)...)
	}
	if len(b)%128 != 0 {
		panic("this should be padded already")
	}
	bNoPad := make([]byte, len(b)-len(b)/128)
	fr32.Unpad(bNoPad, b)

	unpaddedIndexSize := int64(MaxIndexEntriesInDeal(d.DealSize) * EntrySize)
	unpaddedIndexSize = unpaddedIndexSize - unpaddedIndexSize/128
	paddingSize := unpaddedIndexSize - int64(len(bNoPad))

	return io.MultiReader(bytes.NewReader(bNoPad), io.LimitReader(zeroReader{}, paddingSize)), nil
}

// IndexStartPosition returns the expected starting position where the index should be placed
// in the unpadded units
func (d Aggregate) IndexStartPosition() (uint64, error) {
	return DataSegmentIndexStartOffset(d.DealSize), nil
}

func (d Aggregate) IndexSize() (abi.PaddedPieceSize, error) {
	return abi.PaddedPieceSize(uint64(MaxIndexEntriesInDeal(d.DealSize)) * EntrySize), nil
}

// ComputeDealPlacement takes in PieceInfos with Comm and Size,
// computes their placement in the tree and them in form of merkletree.CommAndLoc
// also returns number of bytes required and any errors
func ComputeDealPlacement(dealInfos []abi.PieceInfo) ([]merkletree.CommAndLoc, uint64, error) {
	res := make([]merkletree.CommAndLoc, len(dealInfos))
	offset := uint64(0)
	for i, di := range dealInfos {
		sizeInNodes := uint64(di.Size) / merkletree.NodeSize
		comm, err := commcid.CIDToPieceCommitmentV1(di.PieceCID)
		if err != nil {
			return nil, 0, xerrors.Errorf("converting to piece commitment: %w", err)
		}
		res[i].Comm = *(*merkletree.Node)(comm)

		res[i].Loc.Level = util.Log2Ceil(sizeInNodes)     // level is log2(sizeInNodes)
		index := (offset + sizeInNodes - 1) / sizeInNodes // idx is ceil(offset/sizeInNodes)
		res[i].Loc.Index = index

		offset = (index + 1) * sizeInNodes // select the next index at ni.lvl and go back to nodewise
	}
	return res, offset, nil
}

type zeroReader struct{}

var _ io.Reader = zeroReader{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}
