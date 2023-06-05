package datasegment

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/filecoin-project/go-data-segment/util"

	commcid "github.com/filecoin-project/go-fil-commcid"
	commp "github.com/filecoin-project/go-fil-commp-hashhash"
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
		assert.NoError(t, err)
		aux, err := ip.ComputeExpectedAuxData(VerifierDataForPieceInfo(pi))
		assert.NoError(t, err)
		assert.Equal(t, InclusionAuxData{CommPa: pcid, SizePa: a.DealSize}, *aux)
	}
}

func TestAggregateObjectReader(t *testing.T) {
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

	p0, err := os.Open("testdata/sample_aggregate/cat.png.car")
	require.NoError(t, err)

	p1, err := os.Open("testdata/sample_aggregate/Verifiable Data Aggregation.png.car")
	require.NoError(t, err)

	objectReader, err := a.AggregateObjectReader([]io.Reader{p0, p1})
	require.NoError(t, err)

	commpHasher := commp.Calc{}
	_, err = io.CopyBuffer(&commpHasher, objectReader, make([]byte, commpHasher.BlockSize()*128))
	assert.NoError(t, err)

	commp, paddedSize, err := commpHasher.Digest()
	assert.NoError(t, err)
	pieceCid := Must(commcid.PieceCommitmentV1ToCID(commp))
	assert.Equal(t, uint64(dealSize), uint64(paddedSize))
	assert.Equal(t, cid.MustParse("baga6ea4seaqnqkeoqevjjjfe46wo2lpfclcbmkyms4wkz5srou3vzmr3w3c72bq"), pieceCid)
	assert.Equal(t, pieceCid, Must(a.PieceCID()))

}

func TestIndexCID(t *testing.T) {
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
	dealSize := abi.PaddedPieceSize(1 << 30)
	a, err := NewAggregate(dealSize, pieceInfos)
	assert.NoError(t, err)
	assert.NotNil(t, a)

	indexReader, err := a.IndexReader()
	assert.NoError(t, err)

	indexCID, err := a.IndexPieceCID()
	assert.NoError(t, err)

	commpHasher := commp.Calc{}
	_, err = io.CopyBuffer(&commpHasher, indexReader, make([]byte, commpHasher.BlockSize()*128))
	assert.NoError(t, err)

	commp, paddedSize, err := commpHasher.Digest()
	assert.NoError(t, err)
	indexCID2 := Must(commcid.PieceCommitmentV1ToCID(commp))
	assert.Equal(t, uint64(Must(a.IndexSize())), uint64(paddedSize))
	assert.Equal(t, indexCID, indexCID2)
}

func TestProofForPieceInfo(t *testing.T) {
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
	dealSize := abi.PaddedPieceSize(1 << 30)
	a, err := NewAggregate(dealSize, pieceInfos)
	assert.NoError(t, err)
	assert.NotNil(t, a)

	for _, pi := range pieceInfos {
		proof, err := a.ProofForPieceInfo(pi)
		assert.NoError(t, err)
		ia, err := proof.ComputeExpectedAuxData(VerifierDataForPieceInfo(pi))
		assert.NoError(t, err)
		assert.Equal(t, Must(a.PieceCID()), ia.CommPa)
	}
}

func TestAlvin(t *testing.T) {
	pieceInfos := []abi.PieceInfo{
		{
			PieceCID: cid.MustParse("baga6ea4seaqhiopmpmv2iztddng5ado4dm4yzzv22yfe6vhr7rtsth6lkwym6ki"),
			Size:     abi.PaddedPieceSize(524288),
		},
		{
			PieceCID: cid.MustParse("baga6ea4seaqnv5iuavkp6dx645qy2h4qiqptnmbshduvdbwlfvj7mk7yz7lr6dy"),
			Size:     abi.PaddedPieceSize(524288),
		},
		{
			PieceCID: cid.MustParse("baga6ea4seaqjikavnkvhiy73eyhhm7nmki2v7iqq3eivxyzfiezspivfydblala"),
			Size:     abi.PaddedPieceSize(524288),
		},
		{
			PieceCID: cid.MustParse("baga6ea4seaqk4ezncvnugzxhuafadt5jep5vn4izylh772jtlopiufymbu4dmlq"),
			Size:     abi.PaddedPieceSize(524288),
		},
		{
			PieceCID: cid.MustParse("baga6ea4seaqfusknxkmyf6ehrz5keq3ij65hmz2i5hyk2cxbmo4s7pujbzrqccq"),
			Size:     abi.PaddedPieceSize(524288),
		},
	}

	dealSize := abi.PaddedPieceSize(Must(util.CeilPow2(5 * 524288)))
	a, err := NewAggregate(dealSize, pieceInfos)
	assert.NoError(t, err)
	require.NotNil(t, a)

	for _, pi := range pieceInfos {
		proof, err := a.ProofForPieceInfo(pi)
		assert.NoError(t, err)
		ia, err := proof.ComputeExpectedAuxData(VerifierDataForPieceInfo(pi))
		require.NoError(t, err)
		assert.Equal(t, Must(a.PieceCID()), ia.CommPa)
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

	fmt.Printf("getting index cid\n")
	indexCid, err := a.IndexPieceCID()
	assert.NoError(t, err)
	fmt.Fprintf(f, "CID: %s\n", indexCid)
	fmt.Fprintf(f, "Piece size: %dB\n", nbytes)
	fmt.Fprintf(f, "Piece size in bytes: %d\n", nbytes)

	f, err = os.Create("testdata/sample_aggregate/deal.data")
	require.NoError(t, err)
	err = f.Truncate(int64(abi.PaddedPieceSize(dealSize).Unpadded()))
	require.NoError(t, err)

	{
		_, err = f.Seek(int64(a.Index.Entries[0].UnpaddedOffest()), io.SeekStart)
		require.NoError(t, err)
		p0, err := os.Open("testdata/sample_aggregate/cat.png.car")
		require.NoError(t, err)
		_, err = io.Copy(f, p0)
		require.NoError(t, err)
	}
	{
		p1, err := os.Open("testdata/sample_aggregate/Verifiable Data Aggregation.png.car")
		require.NoError(t, err)
		_, err = f.Seek(int64(a.Index.Entries[1].UnpaddedOffest()), io.SeekStart)
		require.NoError(t, err)
		_, err = io.Copy(f, p1)
		require.NoError(t, err)
		err = p1.Close()
		assert.NoError(t, err)
	}
	{
		index_start, err := a.IndexStartPosition()
		require.NoError(t, err)
		_, err = f.Seek(int64(index_start), io.SeekStart)
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
		indexStart := DataSegmentIndexStartOffset(dealSize)
		f.Seek(int64(indexStart), io.SeekStart)

		indexData, err := ParseDataSegmentIndex(f)
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

	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)

	commpHasher := commp.Calc{}
	_, err = io.CopyBuffer(&commpHasher, f, make([]byte, commpHasher.BlockSize()*128))
	assert.NoError(t, err)

	commp, paddedSize, err := commpHasher.Digest()
	assert.NoError(t, err)
	pieceCid := Must(commcid.PieceCommitmentV1ToCID(commp))
	assert.Equal(t, uint64(dealSize), uint64(paddedSize))
	assert.Equal(t, cid.MustParse("baga6ea4seaqnqkeoqevjjjfe46wo2lpfclcbmkyms4wkz5srou3vzmr3w3c72bq"),
		pieceCid)
	assert.Equal(t, pieceCid, Must(a.PieceCID()))
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
