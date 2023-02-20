package merkletree

import (
	"testing"

	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
)

func TestHybridSunshine(t *testing.T) {
	ht, err := NewHybrid(2)
	assert.NoError(t, err)
	{
		// siplest sunshine test
		td := GrowTreeHashedLeafs([]Node{{0x1}, {}, {}, {}})
		expectedRoot := td.Root()

		err = ht.SetNode(0, 0, &Node{0x1})
		assert.NoError(t, err)

		actualRoot := ht.Root()
		assert.Equal(t, *expectedRoot, actualRoot)
	}
	{
		// resetting to 0 works
		err = ht.SetNode(0, 0, &Node{})
		assert.NoError(t, err)

		actualRoot := ht.Root()
		assert.Equal(t, ZeroCommitmentForLevel(2), actualRoot)
	}
	{
		td := GrowTreeHashedLeafs([]Node{{}, {}, {}, {0x01}})
		expectedRoot := td.Root()

		err = ht.SetNode(0, 3, &Node{0x1})
		assert.NoError(t, err)

		actualRoot := ht.Root()
		assert.Equal(t, *expectedRoot, actualRoot)
	}
}

func TestHybridAsGenerateUnsealedCID(t *testing.T) {

	pieceInfos := []abi.PieceInfo{
		{PieceCID: Must(cid.Parse("baga6ea4seaqknzm22isnhsxt2s4dnw45kfywmhenngqq3nc7jvecakoca6ksyhy")), Size: 256 << 20},  // https://filfox.info/en/deal/3755444
		{PieceCID: Must(cid.Parse("baga6ea4seaqnq6o5wuewdpviyoafno4rdpqnokz6ghvg2iyeyfbqxgcwdlj2egi")), Size: 1024 << 20}, // https://filfox.info/en/deal/3755443
		{PieceCID: Must(cid.Parse("baga6ea4seaqpixk4ifbkzato3huzycj6ty6gllqwanhdpsvxikawyl5bg2h44mq")), Size: 512 << 20},  // https://filfox.info/en/deal/3755442
		{PieceCID: Must(cid.Parse("baga6ea4seaqaxwe5dy6nt3ko5tngtmzvpqxqikw5mdwfjqgaxfwtzenc6bgzajq")), Size: 512 << 20},  // https://filfox.info/en/deal/3755608
		{PieceCID: Must(cid.Parse("baga6ea4seaqpy33nbesa4d6ot2ygeuy43y4t7amc4izt52mlotqenwcmn2kyaai")), Size: 1024 << 20}, // https://filfox.info/en/deal/3755679
		{PieceCID: Must(cid.Parse("baga6ea4seaqphvv4x2s2v7ykgc3ugs2kkltbdeg7icxstklkrgqvv72m2v3i2aa")), Size: 256 << 20},  // https://filfox.info/en/deal/3755680
		{PieceCID: Must(cid.Parse("baga6ea4seaqf5u55znk6jwhdsrhe37emzhmehiyvjxpsww274f6fiy3h4yctady")), Size: 512 << 20},  // https://filfox.info/en/deal/3755754
		{PieceCID: Must(cid.Parse("baga6ea4seaqa3qbabsbmvk5er6rhsjzt74beplzgulthamm22jue4zgqcuszofi")), Size: 1024 << 20}, // https://filfox.info/en/deal/3755803
		{PieceCID: Must(cid.Parse("baga6ea4seaqiekvf623muj6jpxg6vsqaikyw3r4ob5u7363z7zcaixqvfqsc2ji")), Size: 256 << 20},  // https://filfox.info/en/deal/3755883
		{PieceCID: Must(cid.Parse("baga6ea4seaqhsewv65z2d4m5o4vo65vl5o6z4bcegdvgnusvlt7rao44gro36pi")), Size: 512 << 20},  // https://filfox.info/en/deal/3755882
	}
	expCommD := *(*Node)(Must(commcid.CIDToPieceCommitmentV1(
		Must(cid.Parse("baga6ea4seaqiw3gbmstmexb7sqwkc5r23o3i7zcyx5kr76pfobpykes3af62kca")))))

	type nodeInfo struct {
		lvl int
		idx uint64
		n   Node
	}

	dealInfos := make([]DealInfo, 0, len(pieceInfos))
	for _, pi := range pieceInfos {
		dealInfos = append(dealInfos, DealInfo{
			Comm: *(*Node)(Must(commcid.CIDToPieceCommitmentV1(pi.PieceCID))),
			Size: uint64(pi.Size),
		})
	}
	_, err := ComputeDealPlacement(dealInfos)
	assert.NoError(t, err)

	ht, err := NewHybrid(30)
	assert.NoError(t, err)

	err = PlaceDeals(&ht, dealInfos)
	assert.NoError(t, err)

	assert.Equal(t, expCommD, ht.Root())

	for i, n := range dealInfos {
		proof, err := ht.CollectProof(n.Level, n.Index)
		assert.NoError(t, err, "node info %d", i)
		root, err := proof.ComputeRoot(&n.Comm)
		assert.NoError(t, err, "node info %d", i)
		assert.Equal(t, expCommD, *root)
	}
}

func Must[T any](val T, err error) T {
	if err != nil {
		panic("err")
	}
	return val
}
