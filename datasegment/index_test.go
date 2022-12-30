package datasegment

import (
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

// PUBLIC METHODS
func TestIndexSerialization(t *testing.T) {
	entry1 := Entry{
		CommDs: fr32.Fr32{},
		Offset: 123,
		Size:   12222,
		Check:  Checksum{},
	}
	entry2 := Entry{
		CommDs: fr32.Fr32{},
		Offset: 311,
		Size:   22221,
		Check:  Checksum{},
	}
	index, err := MakeIndex([]Entry{entry1, entry2}, 100000)
	assert.Nil(t, err)
	assert.Equal(t, 2, index.NumberEntries())
	assert.Equal(t, 2*64, index.IndexSize())
	assert.Equal(t, 100000, index.DealSize())
	assert.Equal(t, 100000-2*64, index.Start())
	assert.Equal(t, entry1, index.Entry(0))
	assert.Equal(t, entry2, index.Entry(1))
	encoded, err := SerializeIndex(index)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)
	decoded, errDec := DeserializeIndex(encoded)
	assert.Nil(t, errDec)
	assert.NotNil(t, decoded)
	assert.Equal(t, index.NumberEntries(), decoded.NumberEntries())
	assert.Equal(t, index.IndexSize(), decoded.IndexSize())
	assert.Equal(t, index.Start(), decoded.Start())
	assert.Equal(t, index.Entry(0), decoded.Entry(0))
	assert.Equal(t, index.Entry(1), decoded.Entry(1))
	assert.Equal(t, index.DealSize(), decoded.DealSize())
	assert.True(t, reflect.DeepEqual(index, decoded))
}

// NEGATIVE TESTS
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
	data = indexData{dealSize: 15, entries: make([]Entry, 0)}
	serialized, err = SerializeIndex(data)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
}

func TestNegativeValidationDealSize(t *testing.T) {
	// Too small deal
	entry := Entry{
		CommDs: fr32.Fr32{},
		Offset: 123,
		Size:   12222,
		Check:  Checksum{},
	}
	index := indexData{-1, []Entry{entry}}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationEntriesSize(t *testing.T) {
	// Negative size
	entry := Entry{
		CommDs: fr32.Fr32{},
		Offset: 1,
		Size:   -100,
		Check:  Checksum{},
	}
	index := indexData{-1, []Entry{entry}}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationEntriesOffset(t *testing.T) {
	// Negative offset
	entry := Entry{
		CommDs: fr32.Fr32{},
		Offset: -1,
		Size:   324,
		Check:  Checksum{},
	}
	index := indexData{-1, []Entry{entry}}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationEntriesAmount(t *testing.T) {
	// Empty entries
	index := indexData{-1, make([]Entry, 0)}
	assert.False(t, validateIndexStructure(index))
}

func TestNegativeValidationIndexNil(t *testing.T) {
	// nil
	serialized, err := SerializeIndex(nil)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
}
