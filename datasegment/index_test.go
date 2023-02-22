package datasegment

import (
	"fmt"
	"testing"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/stretchr/testify/assert"
)

// HELPER METHODS

type Node = merkletree.Node

func invalidEntry1() SegmentDesc {
	return SegmentDesc{
		CommDs:   Node{},
		Offset:   123,
		Size:     12222,
		Checksum: [ChecksumSize]byte{},
	}
}
func invalidEntry2() SegmentDesc {
	return SegmentDesc{
		CommDs:   Node{},
		Offset:   311,
		Size:     22221,
		Checksum: [ChecksumSize]byte{0x1},
	}
}

// makes an index without valid checksums
func invalidIndex() IndexData {
	index := IndexData{
		Entries: []SegmentDesc{invalidEntry1(), invalidEntry2()},
	}
	return index
}

func validIndex(t *testing.T) IndexData {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}
	entry1, err1 := MakeDataSegmentIdx(&comm1, 128, 256)
	assert.Nil(t, err1)
	entry2, err2 := MakeDataSegmentIdx(&comm2, 128<<5, 128<<4)
	assert.Nil(t, err2)
	index, err3 := MakeIndex([]SegmentDesc{entry1, entry2})
	assert.Nil(t, err3)
	return *index
}

func TestValidateEntry(t *testing.T) {
	tests := []struct {
		sd  SegmentDesc
		err string
	}{
		{sd: SegmentDesc{Offset: 0, Size: 0}.withUpdatedChecksum()},
		{sd: SegmentDesc{Offset: 128, Size: 128 * 3249}.withUpdatedChecksum()},
		{sd: SegmentDesc{Offset: 128 * 323221, Size: 128 * 3249}.withUpdatedChecksum()},
		{sd: SegmentDesc{Offset: 128*323221 + 1, Size: 128 * 3249}.withUpdatedChecksum(), err: "offset"},
		{sd: SegmentDesc{Offset: 128 * 323221, Size: 128*3249 + 1}.withUpdatedChecksum(), err: "size"},
		{sd: SegmentDesc{Offset: 128 * 323221, Size: 128 * 3249}, err: "checksum"},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("testcase-%d", i), func(t *testing.T) {
			err := tc.sd.Validate()
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrValidation)
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

// PUBLIC METHODS
func TestIndexSerializationValidation(t *testing.T) {
	index := validIndex(t)
	encoded, err := index.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, encoded)
	var decoded IndexData
	err = decoded.UnmarshalBinary(encoded)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
	err = decoded.Validate()
	assert.NoError(t, err)
	assert.Equal(t, index, decoded)
}

// PRIVATE METHODS
func TestIndexSerialization(t *testing.T) {
	index := invalidIndex()
	assert.Equal(t, 2, index.NumberEntries())
	assert.Equal(t, uint64(2*64), index.IndexSize())
	encoded, err := index.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, encoded)
	var decoded IndexData
	err = decoded.UnmarshalBinary(encoded)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
	assert.Equal(t, index.NumberEntries(), decoded.NumberEntries())
	assert.Equal(t, index.IndexSize(), decoded.IndexSize())
	assert.Equal(t, index.SegmentDesc(0), decoded.SegmentDesc(0))
	assert.Equal(t, index.SegmentDesc(1), decoded.SegmentDesc(1))
	assert.Equal(t, index, decoded)
}

func TestIndexLargeSizes(t *testing.T) {
	index := validIndex(t)
	MakeIndex(index.Entries)
}

// NEGATIVE TESTS
func TestSegmentEntryNegativeMakeError(t *testing.T) {
	en := invalidEntry1()
	en, err := MakeDataSegmentIdxWithChecksum((*fr32.Fr32)(&en.CommDs), en.Offset, en.Size, &en.Checksum)
	assert.Error(t, err)
	assert.Empty(t, en)
}

func TestSegmentEntryValidateFail(t *testing.T) {
	en := invalidEntry1()
	err := en.Validate()
	assert.ErrorIs(t, err, ErrValidation)
}

func TestIndexInvalidEntries(t *testing.T) {
	index := invalidIndex()
	b, err := index.MarshalBinary()
	assert.NoError(t, err)
	assert.NotEmpty(t, b)
	var decoded IndexData
	err = decoded.UnmarshalBinary(b)
	assert.NoError(t, err)
	assert.Equal(t, index, decoded)
	err = index.Validate()
	assert.ErrorIs(t, err, ErrValidation)
	err = decoded.Validate()
	assert.ErrorIs(t, err, ErrValidation)

}

func TestNegativeIndexCreation(t *testing.T) {
	// Nil
	index, err := MakeIndex(nil)
	assert.Error(t, err)
	assert.Nil(t, index)
}

func TestNegativeSerialization(t *testing.T) {
	// nil entries
	data := &IndexData{Entries: nil}
	serialized, err := SerializeIndex(data)
	assert.Error(t, err)
	assert.Nil(t, serialized)

	// Empty entries
	data = &IndexData{Entries: make([]SegmentDesc, 0)}
	serialized, err = SerializeIndex(data)
	assert.Error(t, err)
	assert.Nil(t, serialized)
}

func TestNegativeSerializationIndexNil(t *testing.T) {
	// nil
	serialized, err := SerializeIndex(nil)
	assert.Error(t, err)
	assert.Nil(t, serialized)
}

func TestDealSizeSmallerThanSegmentDesciptions(t *testing.T) {
	// Too small deal
	en := SegmentDesc{
		CommDs:   Node{},
		Offset:   123,
		Size:     12222,
		Checksum: [ChecksumSize]byte{},
	}
	index := IndexData{Entries: []SegmentDesc{en}}
	assert.Error(t, validateIndexStructure(&index))
}

func TestNegativeMakeDescWrongSegments(t *testing.T) {
	segments := make([]merkletree.Node, 10)
	sizes := make([]uint64, 11)
	_, err := MakeSegDescs(segments, sizes)
	assert.Error(t, err)
}
