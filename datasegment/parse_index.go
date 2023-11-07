package datasegment

import (
	"context"
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
	fromBack = fromBack - fromBack/128 // safe because EntrySize = 64 and min(MaxIndexEntriesInDeal(x)) = 4
	return uint64(dealSize.Unpadded()) - fromBack
}

// ParseDataSegmentIndex is a synchronous API on top of ParseDataSegmentIndexAsync
func ParseDataSegmentIndex(unpaddedReader io.Reader) (IndexData, error) {
	allEntries := []SegmentDesc{}
	results := make(chan *SegmentDesc)
	var err error
	go func() {
		err = ParseDataSegmentIndexAsync(context.Background(), unpaddedReader, results)
		close(results)
	}()

	for res := range results {
		allEntries = append(allEntries, *res)
	}

	if err != nil {
		return IndexData{}, err
	}

	return IndexData{Entries: allEntries}, nil
}

// ParseDataSegmentIndexAsync takes in a reader of of unppaded deal data, it should start at offset
// returned by DataSegmentIndexStartOffset
// After parsing use IndexData#ValidEntries() to gather valid data segments
func ParseDataSegmentIndexAsync(ctx context.Context, unpaddedReader io.Reader, results chan<- *SegmentDesc) error {
	unpaddedBuf := make([]byte, 127)
	paddedBuf := make([]byte, 128)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_, err := io.ReadFull(unpaddedReader, unpaddedBuf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				} else {
					return xerrors.Errorf("reading 127 bytes from parsing: %w", err)
				}
			}

			fr32.Pad(unpaddedBuf, paddedBuf)

			en1 := SegmentDesc{}
			en1.UnmarshalBinary(paddedBuf[:EntrySize])
			en2 := SegmentDesc{}
			en2.UnmarshalBinary(paddedBuf[EntrySize:])
			results <- &en1
			results <- &en2
		}
	}
}
