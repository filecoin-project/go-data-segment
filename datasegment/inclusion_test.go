package datasegment

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	cid "github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sampleSizes1 = []uint64{
	256 << 20,
	1024 << 20,
	512 << 20,
	512 << 20,
	1024 << 20,
	256 << 20,
	512 << 20,
	1024 << 20,
	256 << 20,
	512 << 20,
}

func commForDeal(x int) merkletree.Node {
	res := merkletree.Node{}
	res[0] = 0xd
	res[1] = 0xe
	res[2] = 0xa
	res[3] = 0x1

	s := fmt.Sprintf("%d", x)
	for i := 5; len(s) != 0; i++ {
		res[i] = s[0] - '0'
		s = s[1:]
	}
	return res
}

func cidForDeal(x int) cid.Cid {
	n := commForDeal(x)
	c, err := commcid.PieceCommitmentV1ToCID(n[:])
	if err != nil {
		panic(err)
	}
	return c
}

func buildDealTree(t *testing.T, containerSize abi.PaddedPieceSize, dealSizes []uint64) (*merkletree.Hybrid, []merkletree.CommAndLoc) {
	ht, err := merkletree.NewHybrid(util.Log2Ceil(uint64(containerSize / merkletree.NodeSize)))
	require.NoError(t, err)
	require.NotNil(t, ht)

	dealInfos := make([]abi.PieceInfo, 0, len(dealSizes))
	for i, ds := range dealSizes {
		dealInfos = append(dealInfos, abi.PieceInfo{
			PieceCID: cidForDeal(i),
			Size:     abi.PaddedPieceSize(ds),
		})
	}

	col, totalSize, err := ComputeDealPlacement(dealInfos)
	require.NoError(t, err)
	assert.LessOrEqual(t, totalSize, containerSize)
	err = ht.BatchSet(col)
	require.NoError(t, err)

	return &ht, col
}
func TestComputeExpectedAuxData1(t *testing.T) {
	var SizePa abi.PaddedPieceSize = 32 << 30
	ht, col := buildDealTree(t, SizePa, sampleSizes1)

	index, err := MakeIndexFromCommLoc(col)

	require.NoError(t, err)
	indexStartNodes := indexAreaStart(SizePa) / merkletree.NodeSize
	for i, e := range index.Entries {
		ns := e.IntoNodes()
		err := ht.SetNode(0, indexStartNodes+2*uint64(i), &ns[0])
		assert.NoError(t, err)
		err = ht.SetNode(0, indexStartNodes+2*uint64(i)+1, &ns[1])
		assert.NoError(t, err)
	}

	root := ht.Root()
	CommPa, err := commcid.PieceCommitmentV1ToCID(root[:])
	require.NoError(t, err)

	expectedAuxData := InclusionAuxData{
		CommPa: CommPa,
		SizePa: SizePa,
	}

	for i, di := range col {
		ip, err := CollectInclusionProof(ht, di, i)
		require.NoError(t, err)
		require.NotNil(t, ip)

		CommPc, err := commcid.PieceCommitmentV1ToCID(di.Comm[:])
		assert.NoError(t, err)
		verifData := InclusionVerifierData{
			CommPc: CommPc,
			SizePc: abi.PaddedPieceSize(1 << di.Loc.Level * merkletree.NodeSize),
		}
		if i == 3 && false {
			fmt.Printf("verifData := %#v\n", verifData.CommPc.Bytes())
			fmt.Printf("incProof := %#v\n", ip)
			fmt.Printf("expectedAux := %#v\n", expectedAuxData.CommPa.Bytes())
		}
		buf := new(bytes.Buffer)
		err = verifData.MarshalCBOR(buf)
		assert.NoError(t, err)
		verifData = InclusionVerifierData{}
		verifData.UnmarshalCBOR(buf)

		newAux, err := ip.ComputeExpectedAuxData(verifData)
		assert.NoError(t, err)
		assert.Equal(t, &expectedAuxData, newAux)
	}
}

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}
