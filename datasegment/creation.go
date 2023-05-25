package datasegment

import (
	"bytes"
	"io"

	"github.com/hashicorp/go-multierror"
	cid "github.com/ipfs/go-cid"
	xerrors "golang.org/x/xerrors"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	abi "github.com/filecoin-project/go-state-types/abi"
)

type Aggregate struct {
	DealSize abi.PaddedPieceSize
	Index    IndexData
	Tree     merkletree.Hybrid
}

// NewAggregate creates the structure for verifiable deal aggregation
// based on target deal size and subdeals that should be included.
func NewAggregate(dealSize abi.PaddedPieceSize, subdeals []abi.PieceInfo) (*Aggregate, error) {
	if err := dealSize.Validate(); err != nil {
		return nil, xerrors.Errorf("invalid dealSize: %w", err)
	}
	maxEntries := MaxIndexEntriesInDeal(dealSize)
	if uint(len(subdeals)) > maxEntries {
		return nil, xerrors.Errorf("too many subdeals for a %d sized deal: %d > %d",
			dealSize, len(subdeals), maxEntries)
	}
	cl, totalSize, err := ComputeDealPlacement(subdeals)
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

	agg := Aggregate{
		DealSize: dealSize,
		Index:    *index,
		Tree:     ht,
	}

	return &agg, nil
}

// ProofForPieceInfo searches for piece within the Aggregate based on PieceInfo and gathers all the
// information required to produce a proof.
func (a Aggregate) ProofForPieceInfo(d abi.PieceInfo) (*InclusionProof, error) {
	comm, err := commcid.CIDToPieceCommitmentV1(d.PieceCID)
	if err != nil {
		return nil, xerrors.Errorf("convering cid to commitment: %w", err)
	}
	index := -1
	for i, ie := range a.Index.Entries {
		if bytes.Equal(ie.CommDs[:], comm) && ie.Size == uint64(d.Size) {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, xerrors.Errorf("entry for a piece with this PieceInfo was not found in Aggregate")
	}

	return a.ProofForIndexEntry(index)
}

// ProofForIndexEntry gathers information required to produce an InclusionProof based on the index
// of data within the DataSegment Index.
func (a Aggregate) ProofForIndexEntry(idx int) (*InclusionProof, error) {
	e := a.Index.Entries[idx]
	commLoc := e.CommAndLoc()
	ip, err := CollectInclusionProof(&a.Tree, commLoc, idx)
	if err != nil {
		return nil, xerrors.Errorf("collecting inclusion proof: %w", err)
	}

	return ip, nil
}

// PieceCID returns the PieceCID of the deal containng all subdeals and the index
func (a Aggregate) PieceCID() (cid.Cid, error) {
	n := a.Tree.Root()
	return commcid.PieceCommitmentV1ToCID(n[:])
}

func (a Aggregate) indexLoc() merkletree.Location {
	level := util.Log2Ceil(EntrySize / merkletree.NodeSize * uint64(MaxIndexEntriesInDeal(a.DealSize)))
	index := uint64(1)<<(a.Tree.MaxLevel()-level) - 1
	return merkletree.Location{Level: level, Index: index}
}

// IndexPieceCID returns the PieceCID of the index
func (a Aggregate) IndexPieceCID() (cid.Cid, error) {
	l := a.indexLoc()
	n, err := a.Tree.GetNode(l.Level, l.Index)
	if err != nil {
		return cid.Undef, xerrors.Errorf("getting node: %w", err)
	}
	return commcid.PieceCommitmentV1ToCID(n[:])
}

// IndexReader returns a reader for the index containing unpadded bytes of the index
func (a Aggregate) IndexReader() (io.Reader, error) {
	b, err := a.Index.MarshalBinary()
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

	unpaddedIndexSize := int64(MaxIndexEntriesInDeal(a.DealSize) * EntrySize)
	unpaddedIndexSize = unpaddedIndexSize - unpaddedIndexSize/128
	paddingSize := unpaddedIndexSize - int64(len(bNoPad))

	return io.MultiReader(bytes.NewReader(bNoPad), io.LimitReader(zeroReader{}, paddingSize)), nil
}

// IndexStartPosition returns the expected starting position where the index should be placed
// in the unpadded units
func (a Aggregate) IndexStartPosition() (uint64, error) {
	return DataSegmentIndexStartOffset(a.DealSize), nil
}

func (a Aggregate) IndexSize() (abi.PaddedPieceSize, error) {
	size := abi.PaddedPieceSize(uint64(MaxIndexEntriesInDeal(a.DealSize)) * EntrySize)
	if err := size.Validate(); err != nil {
		return abi.PaddedPieceSize(1<<64 - 1), xerrors.Errorf("validating index size %v, report this: %w", size, err)
	}
	return size, nil
}

// AggregateStreamReader creates a reader for the whole aggregate, including the index.
// The subPieceReaders should be passed in the same order as subdeals in the construction call
// of the Aggregate.
// AggregateStreamReader assumes a non-manipulated Index as created by the Aggregate constructor.
func (a Aggregate) AggregateObjectReader(subPieceReaders []io.Reader) (io.Reader, error) {
	if len(subPieceReaders) != len(a.Index.Entries) {
		return nil, xerrors.Errorf("passed different number of subPieceReaders than subPieces: %d != %d", len(subPieceReaders), len(a.Index.Entries))
	}
	readers := []io.Reader{}
	add := func(r ...io.Reader) {
		readers = append(readers, r...)
	}

	offset := int64(0)
	addPiece := func(r io.Reader, targetOffset, targetLength int64) error {
		if offset > targetOffset {
			return xerrors.Errorf("current aggregate offset is greater"+
				" than expected offset from the index. %d > %d", offset, targetOffset)
		}
		if offset != targetOffset {
			add(io.LimitReader(zeroReader{}, int64(targetOffset-offset)))
		}

		// NOTE: maybe some kind of check that the `r` was exhausted
		add(io.LimitReader(io.MultiReader(r, zeroReader{}), int64(targetLength)))
		offset = targetOffset + targetLength
		return nil
	}

	var errs error
	for i := 0; i < len(subPieceReaders); i++ {
		spEntry := a.Index.Entries[i]
		spOffset := spEntry.UnpaddedOffest()
		spLen := spEntry.UnpaddedLength()

		if err := addPiece(subPieceReaders[i], int64(spOffset), int64(spLen)); err != nil {
			errs = multierror.Append(errs, xerrors.Errorf("subpiece %d: %w", i, err))
		}
	}

	{
		var indexErrs error
		indexReader, err := a.IndexReader()
		if err != nil {
			indexErrs = multierror.Append(indexErrs, err)
		}
		indexStart, err := a.IndexStartPosition()
		if err != nil {
			indexErrs = multierror.Append(indexErrs, err)
		}
		indexLength, err := a.IndexSize()
		if err != nil {
			indexErrs = multierror.Append(indexErrs, err)
		}
		if indexErrs == nil {
			if err := addPiece(indexReader,
				int64(indexStart), int64(indexLength.Unpadded())); err != nil {
				errs = multierror.Append(errs, err)
			}
		} else {
			errs = multierror.Append(errs, indexErrs)
		}
	}

	if errs != nil {
		return nil, errs
	}

	return io.MultiReader(readers...), nil
}

// ComputeDealPlacement takes in PieceInfos with Comm and Size,
// computes their placement in the tree and them in form of merkletree.CommAndLoc
// also returns number of bytes required and any errors
func ComputeDealPlacement(dealInfos []abi.PieceInfo) ([]merkletree.CommAndLoc, uint64, error) {
	res := make([]merkletree.CommAndLoc, len(dealInfos))
	offset := uint64(0)
	for i, di := range dealInfos {
		if err := di.Size.Validate(); err != nil {
			return nil, 0, xerrors.Errorf("subpiece %d: size doesn't validate: %w", i, err)
		}
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
	return res, offset * merkletree.NodeSize, nil
}

type zeroReader struct{}

var _ io.Reader = zeroReader{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}
