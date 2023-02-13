package datasegment

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	"github.com/stretchr/testify/assert"
)

// HELPER METHODS
func getLeafs(startIdx int, amount int) [][]byte {
	leafs := make([][]byte, amount)
	for i := startIdx; i < startIdx+amount; i++ {
		singletonInput, _ := hex.DecodeString("deadbeef")
		singletonInput[0] ^= byte(i)
		leafs[i] = singletonInput
	}
	return leafs
}

// Returns the inclusion, the node that is the root of the subtree inclusion, along with the amount of leafs it should cover
func validInclusion(t *testing.T) (Inclusion, *merkletree.Node, int) {
	leafs := [][]byte{{0x01, 0x02}, {0x03}, {0x04}, {0x05}, {0x06}}
	tree, err := merkletree.GrowTree(leafs)
	assert.NoError(t, err)
	digest := *merkletree.TruncatedHash(leafs[3])
	commDA := fr32.Fr32(digest)
	proofSub, err := tree.ConstructProof(1, 1)
	assert.NoError(t, err)
	proofDs, err := tree.ConstructProof(tree.Depth()-1, 3)
	assert.NoError(t, err)
	return Inclusion{CommDA: commDA, Size: 1234, ProofSubtree: proofSub, ProofDs: proofDs}, tree.Node(1, 1), 3
}

// PUBLIC METHODS
func TestInclusionSerialization(t *testing.T) {
	leafs := [][]byte{{0x01, 0x02}, {0x03}, {0x04}, {0x05}, {0x06}}
	tree, err := merkletree.GrowTree(leafs)
	assert.NoError(t, err)
	commDA := fr32.Fr32{}
	proofSub, err := tree.ConstructProof(1, 1)
	assert.NoError(t, err)
	proofDs, err := tree.ConstructProof(1, 0)
	assert.NoError(t, err)
	structure := Inclusion{CommDA: commDA, Size: 1234, ProofSubtree: proofSub, ProofDs: proofDs}
	encoded, errEnc := SerializeInclusion(structure)
	assert.Nil(t, errEnc)
	assert.NotNil(t, encoded)
	decoded, errDec := DeserializeInclusion(encoded)
	assert.Nil(t, errDec)
	assert.NotNil(t, decoded)
	assert.Equal(t, commDA, decoded.CommDA)
	assert.Equal(t, proofSub.Path(), decoded.ProofSubtree.Path())
	assert.Equal(t, proofSub.Depth(), decoded.ProofSubtree.Depth())
	assert.Equal(t, proofSub.Index(), decoded.ProofSubtree.Index())
	assert.Equal(t, proofDs.Path(), decoded.ProofDs.Path())
	assert.Equal(t, proofDs.Depth(), decoded.ProofDs.Depth())
	assert.Equal(t, proofDs.Index(), decoded.ProofDs.Index())
	assert.Equal(t, 1234, decoded.Size)
}

func TestInclusionSerializationIntegration(t *testing.T) {
	leafs := [][]byte{{0x01, 0x02}, {0x03}, {0x04}, {0x05}, {0x06}}
	tree, err := merkletree.GrowTree(leafs)
	assert.NoError(t, err)
	digest := *merkletree.TruncatedHash(leafs[3])
	commDA := fr32.Fr32(digest)
	proofSub, err := tree.ConstructProof(1, 1)
	assert.NoError(t, err)
	proofDs, err := tree.ConstructProof(tree.Depth()-1, 3)
	assert.NoError(t, err)
	structure := Inclusion{CommDA: commDA, Size: 1234, ProofSubtree: proofSub, ProofDs: proofDs}
	encoded, errEnc := SerializeInclusion(structure)
	assert.Nil(t, errEnc)
	assert.NotNil(t, encoded)
	decoded, errDec := DeserializeInclusion(encoded)
	assert.Nil(t, errDec)
	assert.NotNil(t, decoded)
	assert.Equal(t, commDA, decoded.CommDA)
	assert.True(t, reflect.DeepEqual(proofSub, decoded.ProofSubtree))
	assert.True(t, reflect.DeepEqual(proofDs, decoded.ProofDs))
	assert.Equal(t, proofSub.Path(), decoded.ProofSubtree.Path())
	assert.Equal(t, 1234, decoded.Size)
}

func TestVerifyEntryInclusion(t *testing.T) {
	sizeDA := 400
	offset := uint64(98)
	leafData := getLeafs(0, sizeDA)
	dealTree, err := merkletree.GrowTree(leafData)
	assert.NoError(t, err)
	comm := dealTree.Leafs()[offset]
	// The client's data segment is the leaf at offset
	subtreeProof, err := dealTree.ConstructProof(dealTree.Depth()-1, offset)
	assert.NoError(t, err)
	assert.NoError(t, VerifyInclusion((*fr32.Fr32)(&comm), (*fr32.Fr32)(dealTree.Root()), subtreeProof))
}

func TestVerifySegmentInclusion(t *testing.T) {
	sizeData := uint64(129)
	offset := uint64(98)
	sizeDs := uint64(1)
	leafData := getLeafs(0, int(sizeData))
	dealTree, err := merkletree.GrowTree(leafData)
	assert.NoError(t, err)
	comm := dealTree.Leafs()[offset]
	entry, err2 := MakeDataSegmentIdx((*fr32.Fr32)(&comm), offset, sizeDs)
	assert.Nil(t, err2)
	// We let the client segments be all the leafs
	sizes := make([]uint64, sizeData)
	for i := range sizes {
		sizes[i] = 1
	}
	incTree, indexStart, err := MakeInclusionTree(dealTree.Leafs()[:sizeData], sizes, dealTree)
	assert.NoError(t, err)
	proofDs, err := MakeIndexProof(incTree, offset, indexStart)
	assert.NoError(t, err)
	assert.NoError(t, VerifySegDescInclusion(entry, (*fr32.Fr32)(incTree.Root()), incTree.LeafCount(), proofDs))
}

func TestVerifyInclusionTree(t *testing.T) {
	sizeData := uint64(1235)
	offset := uint64(123)
	leafData := getLeafs(0, int(sizeData))
	dealTree, err := merkletree.GrowTree(leafData)
	assert.NoError(t, err)
	comm := dealTree.Leafs()[offset]
	// We let the client segments be all the leafs
	sizes := make([]uint64, sizeData)
	for i := range sizes {
		sizes[i] = 1
	}
	incTree, indexStart, err := MakeInclusionTree(dealTree.Leafs()[:sizeData], sizes, dealTree)
	assert.NoError(t, err)
	assert.NotNil(t, incTree)

	sizeDA := incTree.LeafCount()

	subtreeProof, err := incTree.ConstructProof(incTree.Depth()-1, offset)
	assert.NoError(t, err)
	assert.NoError(t, VerifyInclusion((*fr32.Fr32)(&comm), (*fr32.Fr32)(incTree.Root()), subtreeProof))
	proofDs, err := MakeIndexProof(incTree, offset, indexStart)
	assert.NoError(t, err)
	assert.NoError(t,
		Validate(
			(*fr32.Fr32)(&comm), 1,
			(*fr32.Fr32)(incTree.Root()), sizeDA,
			subtreeProof, proofDs))
}

type inclusionData struct {
	segmentIdx  uint64
	segmentSize uint64
	segments    int
}

// Make a list of test sizes and return this list along with the total amount of nodes in the leaf tree and the start position of the client segment which we are interested in
// Currently we just use a static segment-size, since otherwise it is hard to automatically ensure proper partitioning of subtrees
// TODO is to ensure that segments distributed correctly in the deal with proper subtree
func testSizes(d inclusionData) ([]uint64, uint64, uint64) {
	sizes := make([]uint64, d.segments)
	var totalUsed, offset uint64
	for j := range sizes {
		if d.segmentIdx != uint64(j) {
			// Round to nearest 2-power
			sizes[j] = 1 << util.Log2Ceil(uint64(d.segmentSize))
		} else {
			// Adjust the segment we care about
			sizes[d.segmentIdx] = d.segmentSize
			offset = totalUsed
		}
		// Round up to nearest 2-power
		totalUsed += 1 << util.Log2Ceil(uint64(sizes[j]))
	}
	return sizes, totalUsed, offset
}

func TestVerifyInclusionTreeSoak(t *testing.T) {
	testData := []inclusionData{
		{
			segmentIdx:  0, // first segment
			segmentSize: 128,
			segments:    42,
		},
		{
			segmentIdx:  41, // last segment
			segmentSize: 1,  // smallest size
			segments:    42,
		},
		{
			segmentIdx:  14, // middle segment
			segmentSize: 11,
			segments:    64,
		},
	}
	for i, data := range testData {
		t.Logf("testdata: %d, %+v", i, data)
		sizes, sizeData, offset := testSizes(data)
		leafData := getLeafs(0, int(sizeData))
		dealTree, err := merkletree.GrowTree(leafData)
		assert.NoError(t, err)

		segments := make([]merkletree.Node, data.segments)
		curOffset := uint64(0)
		for j := range sizes {
			lvl, idx := SegmentRoot(dealTree.Depth(), sizes[j], curOffset)
			segments[j] = *dealTree.Node(lvl, idx)
			curOffset += sizes[j]
		}

		// Ensure that we take include the test segment we want
		dealLvl, dealIdx := SegmentRoot(dealTree.Depth(), data.segmentSize, offset)
		segments[data.segmentIdx] = *dealTree.Node(dealLvl, dealIdx)
		incTree, indexStart, err := MakeInclusionTree(segments, sizes, dealTree)
		assert.NoError(t, err)
		sizeDA := incTree.LeafCount()

		clientLvl, clientIdx := SegmentRoot(incTree.Depth(), data.segmentSize, offset)
		comm := incTree.Node(clientLvl, clientIdx)

		// Sanity check that the client's segment is the one being included in the index
		assert.Equal(t, segments[data.segmentIdx], *comm)
		subtreeProof, err := incTree.ConstructProof(clientLvl, clientIdx)
		assert.NoError(t, err)
		assert.NoError(t, VerifyInclusion((*fr32.Fr32)(comm), (*fr32.Fr32)(incTree.Root()), subtreeProof))

		proofDs, err := MakeIndexProof(incTree, data.segmentIdx, indexStart)
		assert.NoError(t, err)
		assert.NoError(t,
			Validate(
				(*fr32.Fr32)(comm), data.segmentSize,
				(*fr32.Fr32)(incTree.Root()), sizeDA,
				subtreeProof, proofDs,
			))
	}
}

// NEGATIVE TESTS
func TestNegativeInclusionSerializationSize(t *testing.T) {
	inc := Inclusion{
		CommDA:       fr32.Fr32{},
		Size:         0,
		ProofSubtree: nil,
		ProofDs:      nil,
	}
	serialized, err := SerializeInclusion(inc)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
}

func TestNegativeInclusionDeserializeProofEmpty(t *testing.T) {
	_, err := DeserializeInclusion(nil)
	assert.NotNil(t, err)
	_, err = DeserializeInclusion([]byte{})
	assert.NotNil(t, err)
}

func TestNegativeInclusionDeserializeProofSize(t *testing.T) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint64(0))
	assert.NoError(t, err)
	proof, size, err := deserializeProof(buf.Bytes())
	assert.Nil(t, proof)
	assert.Equal(t, -1, size)
	assert.NotNil(t, err)
}

func TestNegativeInclusionDeserializeProofSize2(t *testing.T) {
	encoded := make([]byte, minSizeInclusion)
	_, err := DeserializeInclusion(encoded)
	assert.NotNil(t, err)
}

func TestNegativeInclusionDeserializeProofSize3(t *testing.T) {
	t.Skip()
	inclusion, _, _ := validInclusion(t)
	buf := new(bytes.Buffer)
	err := serializeProof(buf, inclusion.ProofDs)
	assert.NoError(t, err)
	encodedProof := buf.Bytes()
	// Wrong size
	encodedProof[0] += 1
	_, _, errDec := deserializeProof(encodedProof)
	assert.NotNil(t, errDec)
}

func TestNegativeInvalidIndexTreePos(t *testing.T) {
	leafs := [][]byte{{0x01, 0x02}, {0x03}, {0x04}, {0x05}, {0x06}}
	tree, err := merkletree.GrowTree(leafs)
	assert.NoError(t, err)
	proofSub, err := tree.ConstructProof(1, 1)
	assert.NoError(t, err)
	assert.Error(t, validateIndexTreePos(16, proofSub))
}

func TestNegativeVerifySegmentInclusion(t *testing.T) {
	sizeData := uint64(129)
	offset := uint64(98)
	sizeDs := uint64(1)
	leafData := getLeafs(0, int(sizeData))
	dealTree, err := merkletree.GrowTree(leafData)
	assert.NoError(t, err)
	comm := fr32.Fr32(dealTree.Leafs()[offset])
	entry, err2 := MakeDataSegmentIdx(&comm, offset, sizeDs)
	assert.Nil(t, err2)
	// We let the client segments be all the leafs
	sizes := make([]uint64, sizeData)
	for i := range sizes {
		sizes[i] = 1
	}
	incTree, indexStart, err := MakeInclusionTree(dealTree.Leafs()[:sizeData], sizes, dealTree)
	assert.NoError(t, err)
	assert.NotNil(t, incTree)
	sizeDA := incTree.LeafCount()
	proofDs, err := MakeIndexProof(incTree, offset, indexStart)
	assert.NoError(t, err)
	// Wrong number of nodes in the deal
	assert.Error(t, VerifySegDescInclusion(entry, (*fr32.Fr32)(incTree.Root()), 2048, proofDs))
	// Wrong root node
	assert.Error(t, VerifySegDescInclusion(entry, (*fr32.Fr32)(incTree.Node(2, 2)), sizeDA, proofDs))
	// Wrong segment index, consists of 2 nodes
	wrongEntry, err2 := MakeDataSegmentIdx(&comm, offset, 2)
	assert.Nil(t, err2)
	assert.Error(t, VerifySegDescInclusion(wrongEntry, (*fr32.Fr32)(incTree.Node(2, 2)), sizeDA, proofDs))
	// Wrong index
	wrongProofDs, err := MakeIndexProof(incTree, offset+1, indexStart)
	assert.NoError(t, err)
	assert.Error(t, VerifySegDescInclusion(entry, (*fr32.Fr32)(incTree.Root()), sizeDA, wrongProofDs))
}

func TestNegativeValidate(t *testing.T) {
	sizeData := uint64(1235)
	offset := uint64(123)
	leafData := getLeafs(0, int(sizeData))
	dealTree, err := merkletree.GrowTree(leafData)
	assert.NoError(t, err)
	comm := (*fr32.Fr32)(&dealTree.Leafs()[offset])
	// We let the client segments be all the leafs
	sizes := make([]uint64, sizeData)
	for i := range sizes {
		sizes[i] = 1
	}
	incTree, indexStart, err := MakeInclusionTree(dealTree.Leafs()[:sizeData], sizes, dealTree)
	assert.NoError(t, err)
	sizeDA := incTree.LeafCount()
	subtreeProof, err := incTree.ConstructProof(incTree.Depth()-1, offset)
	assert.NoError(t, err)
	assert.NoError(t, VerifyInclusion(comm, (*fr32.Fr32)(incTree.Root()), subtreeProof))
	proofDs, err := MakeIndexProof(incTree, offset, indexStart)
	assert.NoError(t, err)
	assert.NoError(t,
		Validate(
			comm, 1,
			(*fr32.Fr32)(incTree.Root()), sizeDA,
			subtreeProof, proofDs,
		))

	// Wrong sizeDs, should be 1
	assert.Error(t,
		Validate(
			comm, 2,
			(*fr32.Fr32)(incTree.Root()), sizeDA,
			subtreeProof, proofDs,
		))
	// Wrong commitment for subtree, should be based on the deal leafs with offset
	assert.Error(t,
		Validate(
			(*fr32.Fr32)(&dealTree.Leafs()[offset+1]), 1,
			(*fr32.Fr32)(incTree.Root()), sizeDA,
			subtreeProof, proofDs,
		))
	// Wrong number of leafs
	assert.Error(t,
		Validate(
			comm, 1,
			(*fr32.Fr32)(incTree.Root()), 10000,
			subtreeProof, proofDs,
		))
	// Wrong index subtree
	wrongProofDs, err := MakeIndexProof(incTree, offset, indexStart/2)
	assert.NoError(t, err)
	assert.Error(t,
		Validate(
			comm, 1,
			(*fr32.Fr32)(incTree.Root()), sizeDA,
			subtreeProof, wrongProofDs,
		))
	// Wrong index subtree offset
	wrongProofDs2, err := MakeIndexProof(incTree, 42, indexStart)
	assert.NoError(t, err)
	assert.Error(t,
		Validate(
			comm, 1,
			(*fr32.Fr32)(incTree.Root()), sizeDA,
			subtreeProof, wrongProofDs2,
		))
	// Wrong root
	assert.Error(t,
		Validate(
			comm, 1,
			(*fr32.Fr32)(incTree.Node(1, 0)), sizeDA,
			subtreeProof, proofDs,
		))
	// Wrong deal size
	assert.Error(t,
		Validate(
			comm, 1,
			(*fr32.Fr32)(incTree.Root()), 50000,
			subtreeProof, proofDs,
		), "original deal size: %d", sizeDA)
	// Wrong subtree, not a leaf
	wrongSubtreeProof, err := incTree.ConstructProof(incTree.Depth()-2, offset)
	assert.NoError(t, err)
	assert.Error(t,
		Validate(
			comm, 1,
			(*fr32.Fr32)(incTree.Root()), sizeDA,
			wrongSubtreeProof, proofDs,
		))
}
