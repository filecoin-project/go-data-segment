package datasegment

import (
	"errors"
	"io"

	"github.com/filecoin-project/go-data-segment/fr32"
	abi "github.com/filecoin-project/go-state-types/abi"
	xerrors "golang.org/x/xerrors"
)

// DataSegmentIndexStartOffset takes in the padded size of the deal and returns the starting offset
// of data segment index in unpadded units.
func DataSegmentIndexStartOffset(dealSize abi.PaddedPieceSize) uint64 {
	mie := MaxIndexEntriesInDeal(dealSize)
	fromBack := uint64(mie) * uint64(EntrySize)
	fromBack = fromBack / 128 // safe because EntrySize = 64 and min(MaxIndexEntriesInDeal(x)) = 4
	fromBack = 127 * fromBack
	return uint64(dealSize.Unpadded()) - fromBack
}

// ParseDataSegmentIndex takes in a reader of of unppaded deal data, it should start at offset
// returned by DataSegmentIndexStartOffset
// After parsing use IndexData#ValidEntries() to gather valid data segments
func ParseDataSegmentIndex(unpaddedReader io.Reader) (IndexData, error) {
	allEntries := []SegmentDesc{}

	unpaddedBuf := make([]byte, 127)
	paddedBuf := make([]byte, 128)
	for {
		_, err := io.ReadFull(unpaddedReader, unpaddedBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				return IndexData{}, xerrors.Errorf("reading 127 bytes from parsing: %w", err)
			}
		}

		fr32.Pad(unpaddedBuf, paddedBuf)

		en1 := SegmentDesc{}
		en1.UnmarshalBinary(paddedBuf[:EntrySize])
		en2 := SegmentDesc{}
		en2.UnmarshalBinary(paddedBuf[EntrySize:])
		allEntries = append(allEntries, en1, en2)
	}

	return IndexData{Entries: allEntries}, nil
}
