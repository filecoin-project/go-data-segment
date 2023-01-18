package datasegment

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
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

// PUBLIC METHODS
func TestInclusionSerialization(t *testing.T) {
	root := merkletree.Node{}
	commDA := fr32.Fr32{}
	proofSub := merkletree.NewDummyProof(4, 5, &root)
	proofDs := merkletree.NewDummyProof(6, 4233, &root)
	structure := Inclusion{CommDA: commDA, Size: 1234, ProofSubtree: proofSub, ProofDs: proofDs}
	encoded, errEnc := SerializeInclusion(structure)
	assert.Nil(t, errEnc)
	assert.NotNil(t, encoded)
	decoded, errDec := DeserializeInclusion(encoded)
	assert.Nil(t, errDec)
	assert.NotNil(t, decoded)
	assert.Equal(t, commDA, decoded.CommDA)
	assert.Equal(t, proofSub.Path(), decoded.ProofSubtree.Path())
	assert.Equal(t, proofSub.Level(), decoded.ProofSubtree.Level())
	assert.Equal(t, proofSub.Index(), decoded.ProofSubtree.Index())
	assert.Equal(t, proofDs.Path(), decoded.ProofDs.Path())
	assert.Equal(t, proofDs.Level(), decoded.ProofDs.Level())
	assert.Equal(t, proofDs.Index(), decoded.ProofDs.Index())
	assert.Equal(t, 1234, decoded.Size)
}

func TestInclusionSerializationIntegration(t *testing.T) {
	leafs := [][]byte{{0x01, 0x02}, {0x03}, {0x04}, {0x05}, {0x06}}
	tree, err := merkletree.GrowTree(leafs)
	assert.Nil(t, err)
	digest := *merkletree.TruncatedHash(leafs[3])
	commDA := fr32.Fr32{Data: digest.Data}
	proofSub, err := tree.ConstructProof(1, 1)
	assert.Nil(t, err)
	proofDs, err := tree.ConstructProof(tree.Depth()-1, 3)
	assert.Nil(t, err)
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
	offset := 98
	leafData := getLeafs(0, sizeDA)
	dealTree, err := merkletree.GrowTree(leafData)
	comm := dealTree.Leafs()[offset]
	// The client's data segment is the leaf at offset
	subtreeProof, err := dealTree.ConstructProof(dealTree.Depth()-1, offset)
	assert.Nil(t, err)
	assert.True(t, VerifyInclusion(&fr32.Fr32{Data: comm.Data}, &fr32.Fr32{Data: dealTree.Root().Data}, subtreeProof))
}

func TestVerifySegmentInclusion(t *testing.T) {
	sizeDA := 129
	offset := 98
	sizeDs := 1
	leafData := getLeafs(0, sizeDA)
	dealTree, err := merkletree.GrowTree(leafData)
	comm := dealTree.Leafs()[offset]
	entry, err2 := MakeDataSegmentIdx(&fr32.Fr32{Data: comm.Data}, offset, sizeDs)
	assert.Nil(t, err2)
	// We let the client segments be all the leafs
	sizes := make([]int, sizeDA)
	for i := range sizes {
		sizes[i] = 1
	}
	incTree, err := MakeInclusionTree(dealTree.Leafs(), sizes, dealTree)
	assert.Nil(t, err)
	proofDs, err := MakeIndexProof(incTree, offset, sizeDA, sizeDA)
	assert.Nil(t, err)
	assert.True(t, VerifySegDescInclusion(entry, &fr32.Fr32{Data: incTree.Root().Data}, sizeDA, sizeDA, proofDs))
}

func TestVerifyInclusionTree(t *testing.T) {
	sizeDA := 1235
	offset := 123
	leafData := getLeafs(0, sizeDA)
	dealTree, err := merkletree.GrowTree(leafData)
	comm := dealTree.Leafs()[offset]
	// We let the client segments be all the leafs
	sizes := make([]int, sizeDA)
	for i := range sizes {
		sizes[i] = 1
	}
	incTree, err := MakeInclusionTree(dealTree.Leafs(), sizes, dealTree)
	assert.Nil(t, err)
	subtreeProof, err := incTree.ConstructProof(incTree.Depth()-1, offset)
	assert.Nil(t, err)
	assert.True(t, VerifyInclusion(&fr32.Fr32{Data: comm.Data}, &fr32.Fr32{Data: incTree.Root().Data}, subtreeProof))
	proofDs, err := MakeIndexProof(incTree, offset, sizeDA, sizeDA)
	assert.Nil(t, err)
	assert.True(t, Validate(&fr32.Fr32{Data: comm.Data}, 1, &fr32.Fr32{Data: incTree.Root().Data}, sizeDA, sizeDA, subtreeProof, proofDs))
}

type inclusionData struct {
	segmentIdx  int
	segmentSize int
	segments    int
}

// Make a list of test sizes and return this list along with the total amount of nodes in the leaf tree and the start position of the client segment which we are interested in
// Currently we just use a static segment-size, since otherwise it is hard to automatically ensure proper partitioning of subtrees
// TODO is to ensure that segments distributed correctly in the deal with proper subtree
func testSizes(segmentIdx int, segments int, segmentSize int) ([]int, int, int) {
	sizes := make([]int, segments)
	totalUsed := 0
	var offset int
	for j := range sizes {
		if segmentIdx != j {
			// Round to nearest 2-power
			sizes[j] = 1 << util.Log2Ceil(segmentSize)
		} else {
			// Adjust the segment we care about
			sizes[segmentIdx] = segmentSize
			offset = totalUsed
		}
		// Round up to nearest 2-power
		totalUsed += 1 << util.Log2Ceil(sizes[j])
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
			segmentIdx:  14, // middle segment segment
			segmentSize: 11,
			segments:    64,
		},
	}
	for _, data := range testData {
		sizes, sideDA, offset := testSizes(data.segmentIdx, data.segments, data.segmentSize)
		leafData := getLeafs(0, sideDA)
		dealTree, err := merkletree.GrowTree(leafData)
		segments := make([]merkletree.Node, data.segments)
		curOffset := 0
		for j := range sizes {
			lvl, idx := SegmentRoot(dealTree.Depth(), sizes[j], curOffset)
			segments[j] = *dealTree.Node(lvl, idx)
			curOffset += sizes[j]
		}
		// Ensure that we take include the test segment we want
		dealLvl, dealIdx := SegmentRoot(dealTree.Depth(), data.segmentSize, offset)
		segments[data.segmentIdx] = *dealTree.Node(dealLvl, dealIdx)
		incTree, err := MakeInclusionTree(segments, sizes, dealTree)
		assert.Nil(t, err)
		clientLvl, clientIdx := SegmentRoot(incTree.Depth(), data.segmentSize, offset)
		comm := incTree.Node(clientLvl, clientIdx)
		// Sanity check that the client's segment is the one being included in the index
		assert.Equal(t, segments[data.segmentIdx], *comm)
		subtreeProof, err := incTree.ConstructProof(clientLvl, clientIdx)
		assert.Nil(t, err)
		assert.True(t, VerifyInclusion(&fr32.Fr32{Data: comm.Data}, &fr32.Fr32{Data: incTree.Root().Data}, subtreeProof))
		proofDs, err := MakeIndexProof(incTree, data.segmentIdx, sideDA, data.segments)
		assert.Nil(t, err)
		assert.True(t, Validate(&fr32.Fr32{Data: comm.Data}, data.segmentSize, &fr32.Fr32{Data: incTree.Root().Data}, sideDA, data.segments, subtreeProof, proofDs))
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
	assert.Nil(t, err)
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

func TestNegativeDealProofWrongHeight(t *testing.T) {

}
