package datasegment

import (
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

// HELPER METHODS

func invalidEntry1() *SegmentDescIdx {
	return &SegmentDescIdx{
		CommDs:   fr32.Fr32{},
		Offset:   123,
		Size:     12222,
		Checksum: [BytesInChecksum]byte{},
	}
}
func invalidEntry2() *SegmentDescIdx {
	return &SegmentDescIdx{
		CommDs:   fr32.Fr32{},
		Offset:   311,
		Size:     22221,
		Checksum: [BytesInChecksum]byte{},
	}
}

// makes an index without valid checksums
func invalidIndex() *indexData {
	index := indexData{
		dealSize: 100000,
		entries:  []*SegmentDescIdx{invalidEntry1(), invalidEntry2()},
	}
	return &index
}

func validIndex(t *testing.T) *indexData {
	comm1 := fr32.Fr32{Data: [fr32.BytesNeeded]byte{1}}
	comm2 := fr32.Fr32{Data: [fr32.BytesNeeded]byte{2}}
	entry1, err1 := MakeDataSegmentIdx(&comm1, 123, 1222)
	assert.Nil(t, err1)
	entry2, err2 := MakeDataSegmentIdx(&comm2, 132, 342343)
	assert.Nil(t, err2)
	index, err3 := MakeIndex([]*SegmentDescIdx{entry1, entry2}, 1000)
	assert.Nil(t, err3)
	data := index.(indexData)
	return &data
}

// PUBLIC METHODS
func TestIndexSerializationValidation(t *testing.T) {
	index := validIndex(t)
	encoded, err4 := SerializeIndex(index)
	assert.Nil(t, err4)
	assert.NotNil(t, encoded)
	decoded, err5 := DeserializeIndex(encoded)
	assert.Nil(t, err5)
	assert.NotNil(t, decoded)
	assert.True(t, reflect.DeepEqual(*index, decoded.(indexData)))
}

// PRIVATE METHODS
func TestIndexSerialization(t *testing.T) {
	index := invalidIndex()
	assert.Equal(t, 2, index.NumberEntries())
	assert.Equal(t, 2*64, index.IndexSize())
	assert.Equal(t, 100000, index.DealSize())
	assert.Equal(t, 100000-2*64, index.Start())
	encoded, err := serializeIndex(index)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)
	decoded := deserializeIndex(encoded)
	assert.NotNil(t, decoded)
	assert.Equal(t, index.NumberEntries(), decoded.NumberEntries())
	assert.Equal(t, index.IndexSize(), decoded.IndexSize())
	assert.Equal(t, index.Start(), decoded.Start())
	assert.Equal(t, index.SegmentDesc(0), decoded.SegmentDesc(0))
	assert.Equal(t, index.SegmentDesc(1), decoded.SegmentDesc(1))
	assert.Equal(t, index.DealSize(), decoded.DealSize())
	assert.True(t, reflect.DeepEqual(*index, decoded))
}

// NEGATIVE TESTS
func TestNegativeMakeEntryError(t *testing.T) {
	en := invalidEntry1()
	en, err := MakeDataSegmentIdxWithChecksum(&(en.CommDs), en.Offset, en.Size, &en.Checksum)
	assert.NotNil(t, err)
	assert.Nil(t, en)
}

func TestNegativeMakeIndexError(t *testing.T) {
	index := invalidIndex()
	encoded, err := SerializeIndex(index)
	assert.NotNil(t, err)
	assert.Nil(t, encoded)
}

func TestNegativeIndexCreation(t *testing.T) {
	// Nil
	index, err := MakeIndex(nil, 15)
	assert.NotNil(t, err)
	assert.Nil(t, index)
}

func TestNegativeSerialization(t *testing.T) {
	// nil entries
	data := indexData{dealSize: 15, entries: nil}
	serialized, err := SerializeIndex(data)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)

	// Empty entries
	data = indexData{dealSize: 15, entries: make([]*SegmentDescIdx, 0)}
	serialized, err = SerializeIndex(data)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
}

func TestNegativeSerializationIndexNil(t *testing.T) {
	// nil
	serialized, err := SerializeIndex(nil)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
}

func TestNegativeDeserializationIndexIncorrect(t *testing.T) {
	// nil
	serialized, err := DeserializeIndex(nil)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
	// too small size
	serialized, err = DeserializeIndex(make([]byte, minIndexSize-1))
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
	// wrong size
	serialized, err = DeserializeIndex(make([]byte, minIndexSize+1))
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
}

func TestNegativeValidationDealSize(t *testing.T) {
	// Too small deal
	en := SegmentDescIdx{
		CommDs:   fr32.Fr32{},
		Offset:   123,
		Size:     12222,
		Checksum: [BytesInChecksum]byte{},
	}
	index := indexData{-1, []*SegmentDescIdx{&en}}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationEntriesSize(t *testing.T) {
	// Negative size
	en := SegmentDescIdx{
		CommDs:   fr32.Fr32{},
		Offset:   1,
		Size:     -100,
		Checksum: [BytesInChecksum]byte{},
	}
	index := indexData{-1, []*SegmentDescIdx{&en}}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationEntriesOffset(t *testing.T) {
	// Negative offset
	en := SegmentDescIdx{
		CommDs:   fr32.Fr32{},
		Offset:   -1,
		Size:     324,
		Checksum: [BytesInChecksum]byte{},
	}
	index := indexData{-1, []*SegmentDescIdx{&en}}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationEntriesAmount(t *testing.T) {
	// Empty entries
	index := indexData{-1, make([]*SegmentDescIdx, 0)}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationIndexEntriesSize(t *testing.T) {
	index := indexData{
		dealSize: 1,
		entries: []*SegmentDescIdx{{
			CommDs:   fr32.Fr32{},
			Offset:   0,
			Size:     -1,
			Checksum: [BytesInChecksum]byte{},
		},
		}}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationIndexEntriesOffset(t *testing.T) {
	index := indexData{
		dealSize: 1,
		entries: []*SegmentDescIdx{{
			CommDs:   fr32.Fr32{},
			Offset:   -1,
			Size:     1,
			Checksum: [BytesInChecksum]byte{},
		},
		}}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeMakeDescWrongSegments(t *testing.T) {
	segments := make([]merkletree.Node, 10)
	sizes := make([]int, 11)
	_, err := MakeSegDescs(segments, sizes)
	assert.NotNil(t, err)
}

func TestNegativeBadDeserialization(t *testing.T) {
	index := validIndex(t)
	encoded, err1 := serializeIndex(index)
	assert.Nil(t, err1)
	// Make an error in the encoded data
	encoded[7] ^= 0xff
	_, err2 := DeserializeIndex(encoded)
	assert.NotNil(t, err2)
}
