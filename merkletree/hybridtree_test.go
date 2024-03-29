package merkletree

import (
	"os"
	"testing"

	commcid "github.com/filecoin-project/go-fil-commcid"
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

	/*
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
		for _, pi := range pieceInfos {
			dealInfos = append(dealInfos, DealInfo{
				Comm: *(*Node)(Must(commcid.CIDToPieceCommitmentV1(pi.PieceCID))),
				Size: uint64(pi.Size),
			})
		}
	*/
	expCommD := *(*Node)(Must(commcid.CIDToPieceCommitmentV1(
		Must(cid.Parse("baga6ea4seaqiw3gbmstmexb7sqwkc5r23o3i7zcyx5kr76pfobpykes3af62kca")))))

	nodeLoc :=
		[]CommAndLoc{
			{Comm: Node{0xa6, 0xe5, 0x9a, 0xd2, 0x24, 0xd3, 0xca, 0xf3, 0xd4, 0xb8, 0x36, 0xdb, 0x9d,
				0x51, 0x71, 0x66, 0x1c, 0x8d, 0x69, 0xa1, 0xd, 0xb4, 0x5f, 0x4d, 0x48, 0x20, 0x29, 0xc2,
				0x7, 0x95, 0x2c, 0x1f},
				Loc: Location{Level: 23, Index: 0x0}},
			{Comm: Node{0xd8, 0x79, 0xdd, 0xb5, 0x9, 0x61, 0xbe, 0xa8, 0xc3, 0x80, 0x56, 0xbb, 0x91,
				0x1b, 0xe0, 0xd7, 0x2b, 0x3e, 0x31, 0xea, 0x6d, 0x23, 0x4, 0xc1, 0x43, 0xb, 0x98, 0x56,
				0x1a, 0xd3, 0xa2, 0x19},
				Loc: Location{Level: 25, Index: 0x1}},
			{Comm: Node{0xf4, 0x5d, 0x5c, 0x41, 0x42, 0xac, 0x82, 0x6e, 0xd9, 0xe9, 0x9c, 0x9, 0x3e,
				0x9e, 0x3c, 0x65, 0xae, 0x16, 0x3, 0x4e, 0x37, 0xca, 0xb7, 0x42, 0x81, 0x6c, 0x2f, 0xa1,
				0x36, 0x8f, 0xce, 0x32},
				Loc: Location{Level: 24, Index: 0x4}},
			{Comm: Node{0xb, 0xd8, 0x9d, 0x1e, 0x3c, 0xd9, 0xed, 0x4e, 0xec, 0xda, 0x69, 0xb3, 0x35,
				0x7c, 0x2f, 0x4, 0x2a, 0xdd, 0x60, 0xec, 0x54, 0xc0, 0xc0, 0xb9, 0x6d, 0x3c, 0x91, 0xa2,
				0xf0, 0x4d, 0x90, 0x26},
				Loc: Location{Level: 24, Index: 0x5}},
			{Comm: Node{0xfc, 0x6f, 0x6d, 0x9, 0x24, 0xe, 0xf, 0xce, 0x9e, 0xb0, 0x62, 0x53, 0x1c,
				0xde, 0x39, 0x3f, 0x81, 0x82, 0xe2, 0x33, 0x3e, 0xe9, 0x8b, 0x74, 0xe0, 0x46, 0xd8, 0x4c,
				0x6e, 0x95, 0x80, 0x1},
				Loc: Location{Level: 25, Index: 0x3}},
			{Comm: Node{0xf3, 0xd6, 0xbc, 0xbe, 0xa5, 0xaa, 0xff, 0xa, 0x30, 0xb7, 0x43, 0x4b, 0x4a,
				0x52, 0xe6, 0x11, 0x90, 0xdf, 0x40, 0xaf, 0x29, 0xa9, 0x6a, 0x89, 0xa1, 0x5a, 0xff, 0x4c,
				0xd5, 0x76, 0x8d, 0x0},
				Loc: Location{Level: 23, Index: 0x10}},
			{Comm: Node{0x5e, 0xd3, 0xbd, 0xcb, 0x55, 0xe4, 0xd8, 0xe3, 0x94, 0x4e, 0x4d, 0xfc, 0x8c,
				0xc9, 0xd8, 0x43, 0xa3, 0x15, 0x4d, 0xdf, 0x2b, 0x5b, 0x5f, 0xe1, 0x7c, 0x54, 0x63, 0x67,
				0xe6, 0x5, 0x30, 0xf},
				Loc: Location{Level: 24, Index: 0x9}},
			{Comm: Node{0xd, 0xc0, 0x20, 0xc, 0x82, 0xca, 0xab, 0xa4, 0x8f, 0xa2, 0x79, 0x27, 0x33,
				0xff, 0x2, 0x47, 0xaf, 0x26, 0xa2, 0xe6, 0x70, 0x31, 0x9a, 0xd2, 0x68, 0x4e, 0x64, 0xd0,
				0x15, 0x25, 0x97, 0x15},
				Loc: Location{Level: 25, Index: 0x5}},
			{Comm: Node{0x82, 0x2a, 0xa5, 0xf6, 0xb6, 0xca, 0x27, 0xc9, 0x7d, 0xcd, 0xea, 0xca, 0x0,
				0x42, 0xb1, 0x6d, 0xc7, 0x8e, 0xf, 0x69, 0xfd, 0xfb, 0x79, 0xfe, 0x44, 0x4, 0x5e, 0x15,
				0x2c, 0x24, 0x2d, 0x25},
				Loc: Location{Level: 23, Index: 0x18}},
			{Comm: Node{0x79, 0x12, 0xd5, 0xf7, 0x73, 0xa1, 0xf1, 0x9d, 0x77, 0x2a, 0xef, 0x76, 0xab,
				0xeb, 0xbd, 0x9e, 0x4, 0x44, 0x30, 0xea, 0x66, 0xd2, 0x55, 0x5c, 0xff, 0x10, 0x3b, 0x9c,
				0x34, 0x5d, 0xbf, 0x3d},
				Loc: Location{Level: 24, Index: 0xd}}}

	ht, err := NewHybrid(30)
	assert.NoError(t, err)
	err = ht.BatchSet(nodeLoc)
	assert.NoError(t, err)

	assert.Equal(t, expCommD, ht.Root())

	for i, n := range nodeLoc {
		proof, err := ht.CollectProof(n.Loc.Level, n.Loc.Index)
		assert.NoError(t, err, "node info %d", i)
		root, err := proof.ComputeRoot(&n.Comm)
		assert.NoError(t, err, "node info %d", i)
		assert.Equal(t, expCommD, *root)
	}
	err = ht.SetNode(0, 1<<30-1, &Node{0x1})
	assert.NoError(t, err)
	t.Logf("Blocks: %d, size: %d", len(ht.data.subs), len(ht.data.subs)*SparseBlockSize*NodeSize)

	if false {
		f, err := os.CreateTemp("", "ht-encode-*.cbor")
		assert.NoError(t, err)
		err = ht.MarshalCBOR(f)
		assert.NoError(t, err)
		t.Logf("output name: %s", f.Name())
		f.Close()
	}

}

// FuzzSparseIndexing fuzzes for the property that two tuples of (depth, index)
// cannot map to the same spareseIndex
func FuzzSparseIndexing(f *testing.F) {
	const TreeSize = 30
	ht, err := NewHybrid(TreeSize)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(int(0), uint64(0), int(0), uint64(1))
	f.Add(int(0), uint64(0), int(0), uint64(1<<30-1))
	f.Add(int(TreeSize), uint64(0), int(TreeSize-1), uint64(0))
	f.Add(int(TreeSize-1), uint64(0), int(TreeSize-1), uint64(1))
	f.Add(int(TreeSize-6), uint64(0), int(TreeSize-6), uint64(1<<6-1))
	f.Add(int(TreeSize-7), uint64(0), int(TreeSize-7), uint64(1<<7-1))
	f.Add(int(TreeSize-7), uint64(1<<7-1), int(TreeSize-8), uint64(0))
	f.Add(int(TreeSize-15), uint64(1<<15-1), int(TreeSize-16), uint64(0))
	f.Add(int(TreeSize-7), uint64(1<<7-1), int(TreeSize-8), uint64(0))
	f.Add(int(TreeSize-14), uint64(1<<14-1), int(TreeSize-15), uint64(0))

	f.Fuzz(func(t *testing.T, level1 int, index1 uint64, level2 int, index2 uint64) {
		if level1 < 0 || level1 > TreeSize {
			return
		}
		if index1 >= 1<<(TreeSize-level1) {
			return
		}
		if level2 < 0 || level2 > TreeSize {
			return
		}
		if index2 >= 1<<(TreeSize-level2) {
			return
		}
		if index1 == index2 && level1 == level2 {
			return
		}
		if sparseIdx := ht.idxFor(level1, index1); sparseIdx == ht.idxFor(level2, index2) {
			t.Errorf("%d@%d and %d@%d map to the same sparse index: %d", index1, level1, index2, level2, sparseIdx)
		}
	})
}

func Must[T any](val T, err error) T {
	if err != nil {
		panic("err")
	}
	return val
}
