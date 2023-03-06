package datasegment

import (
	"testing"

	abi "github.com/filecoin-project/go-state-types/abi"
	cid "github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
)

func samplePieceInfos1() []abi.PieceInfo {
	res := []abi.PieceInfo{}
	for i, size := range sampleSizes1 {
		res = append(res, abi.PieceInfo{
			Size:     abi.PaddedPieceSize(size),
			PieceCID: cidForDeal(i),
		})
	}

	return res
}

func TestDealCreation(t *testing.T) {
	subPieceInfos := samplePieceInfos1()
	dealSize := abi.PaddedPieceSize(32 << 30)
	a, err := NewAggregate(dealSize, subPieceInfos)
	assert.NoError(t, err)
	assert.NotNil(t, a)
	expectedPieceCID := Must(cid.Cast([]byte{0x1, 0x81, 0xe2, 0x3, 0x92, 0x20, 0x20, 0x3f, 0x46, 0xbc, 0x64,
		0x5b, 0x7, 0xa3, 0xea, 0x2c, 0x4, 0xf0, 0x66, 0xf9, 0x39, 0xdd, 0xf7, 0xe2, 0x69, 0xdd,
		0x77, 0x67, 0x1f, 0x9e, 0x1e, 0x61, 0xa3, 0xa3, 0x79, 0x7e, 0x66, 0x51, 0x27}))
	pcid, err := a.PieceCID()
	assert.NoError(t, err)
	assert.Equal(t, expectedPieceCID, pcid)

	t.Run("index is properly encoded", func(t *testing.T) {
		ir, err := a.IndexReader()
		assert.NoError(t, err)
		parsedIndex, err := ParseDataSegmentIndex(ir)
		assert.NoError(t, err)
		parsedValidEntries, err := parsedIndex.ValidEntries()
		assert.NoError(t, err)
		assert.Equal(t, a.Index.Entries, parsedValidEntries)
	})

}
