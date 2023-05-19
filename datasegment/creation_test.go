package datasegment

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	abi "github.com/filecoin-project/go-state-types/abi"
	cid "github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestAggregateCreation(t *testing.T) {
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

	for _, pi := range subPieceInfos {
		ip, err := a.ProofForPieceInfo(pi)
		aux, err := ip.ComputeExpectedAuxData(VerifierDataForPieceInfo(pi))
		assert.NoError(t, err)
		assert.Equal(t, InclusionAuxData{CommPa: pcid, SizePa: a.DealSize}, *aux)
	}
}

func TestAggregateSample(t *testing.T) {
	pieceInfos := []abi.PieceInfo{
		{
			PieceCID: cid.MustParse("baga6ea4seaqae5ysjdbsr4b5jhotaz5ooh62jrrdbxwygfpkkfjz44kvywycmgy"),
			Size:     abi.UnpaddedPieceSize(520192).Padded(),
		},
		{
			PieceCID: cid.MustParse("baga6ea4seaqnrm2n2g4m23t6rs26obxjw2tjtr7tcho24gepj2naqhevytduyoa"),
			Size:     abi.UnpaddedPieceSize(260096).Padded(),
		},
	}
	dealSize := abi.PaddedPieceSize(1 << 20)
	a, err := NewAggregate(dealSize, pieceInfos)
	assert.NoError(t, err)
	assert.NotNil(t, a)

	f, err := os.Create("testdata/sample_aggregate/index.data")
	require.NoError(t, err)

	r, err := a.IndexReader()
	assert.NoError(t, err)
	nbytes, err := io.Copy(f, r)
	require.NoError(t, err)

	err = f.Close()
	assert.NoError(t, err)

	f, err = os.Create("testdata/sample_aggregate/index.data.commp")
	require.NoError(t, err)

	indexCid, err := a.IndexPieceCID()
	assert.NoError(t, err)
	fmt.Fprintf(f, "CID: %s\n", indexCid)
	fmt.Fprintf(f, "Piece size: %dB\n", nbytes)
	fmt.Fprintf(f, "Piece size in bytes: %d\n", nbytes)

	f, err = os.CreateTemp(t.TempDir(), "deal-*.data")
	require.NoError(t, err)
	err = f.Truncate(int64(abi.PaddedPieceSize(dealSize).Unpadded()))
	require.NoError(t, err)

	{
		_, err = f.Seek(int64(a.Index.Entries[0].UnpaddedOffest()), os.SEEK_SET)
		p0, err := os.Open("testdata/sample_aggregate/cat.png.car")
		require.NoError(t, err)
		_, err = io.Copy(f, p0)
		require.NoError(t, err)
	}
	{
		p1, err := os.Open("testdata/sample_aggregate/Verifiable Data Aggregation.png.car")
		require.NoError(t, err)
		_, err = f.Seek(int64(a.Index.Entries[1].UnpaddedOffest()), os.SEEK_SET)
		require.NoError(t, err)
		_, err = io.Copy(f, p1)
		require.NoError(t, err)
		err = p1.Close()
		assert.NoError(t, err)
	}
	{
		index_start, err := a.IndexStartPosition()
		require.NoError(t, err)
		_, err = f.Seek(int64(index_start), os.SEEK_SET)
		require.NoError(t, err)
		r, err := a.IndexReader()
		require.NoError(t, err)
		nbytes, err = io.Copy(f, r)
		require.NoError(t, err)

		index_size, err := a.IndexSize()
		require.NoError(t, err)
		assert.Equal(t, int64(index_size.Unpadded()), nbytes)
	}
	{
		_, err = f.Seek(0, os.SEEK_SET)
		require.NoError(t, err)
		ff, err := os.Create("testdata/sample_aggregate/deal.data")

		_, err = io.Copy(ff, f)
		require.NoError(t, err)

		err = ff.Close()
		require.NoError(t, err)
	}

	{
		indexStart := DataSegmentIndexStartOffset(dealSize)
		dealData, err := os.Open("testdata/sample_aggregate/deal.data")
		require.NoError(t, err)
		dealData.Seek(int64(indexStart), os.SEEK_SET)

		indexData, err := ParseDataSegmentIndex(dealData)
		require.NoError(t, err)
		assert.Equal(t, Must(a.Index.ValidEntries()), Must(indexData.ValidEntries()))
	}
	indexJson, err := os.Create("testdata/sample_aggregate/index.json")
	require.NoError(t, err)
	entries, err := a.Index.ValidEntries()
	require.NoError(t, err)

	enc := json.NewEncoder(indexJson)
	enc.SetIndent("", "  ")
	err = enc.Encode(entries)
	assert.NoError(t, err)
	indexJson.Close()
}

func TestTwoPieces(t *testing.T) {
	pieces := []abi.PieceInfo{
		{
			Size:     abi.PaddedPieceSize(131072),
			PieceCID: Must(cid.Parse("baga6ea4seaqievout3bskdb76gzldeidkhxo6z5zjrnl2jruvwfwvr2uvvpuwdi")),
		}, {
			Size:     abi.PaddedPieceSize(524288),
			PieceCID: Must(cid.Parse("baga6ea4seaqkzsosscjqdegbhqrlequtm7pbjscwpeqwhrd53cxov5td34vfojy")),
		},
	}
	_, err := NewAggregate(abi.PaddedPieceSize(1<<20), pieces)
	assert.ErrorContains(t, err, "sub-deals are too large")
}

func TestFailWithNonPow2(t *testing.T) {

	_, err := NewAggregate(abi.PaddedPieceSize(1<<20+1), nil)
	assert.ErrorContains(t, err, "padded piece size must be a power of 2")
}
