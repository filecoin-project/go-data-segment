package parsing

import (
	"github.com/filecoin-project/go-data-segment/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

// PUBLIC METHODS TESTS
func TestPadSunshine(t *testing.T) {
	size := 2*types.BytesUsedInFP32 + 5
	unpaddedData := make([]byte, size)
	set1s(&unpaddedData, 0, size)
	// Set 0 at the edge to test edge case
	unpaddedData[0] = 0b11111100
	// Set 0 at the edge to test edge case
	unpaddedData[size-1] = 0b00000011

	res, err := Pad(unpaddedData[:])
	assert.Equal(t, nil, err)
	var firstData [types.BytesUsedInFP32]byte
	set1s(&firstData, 0, types.BytesUsedInFP32)
	firstData[0] = 0b11111100
	firstData[types.BytesUsedInFP32-1] = 0b00111111
	var secondData [types.BytesUsedInFP32]byte
	set1s(&secondData, 0, types.BytesUsedInFP32)
	secondData[types.BytesUsedInFP32-1] = 0b00111111
	var thirdData [types.BytesUsedInFP32]byte
	thirdData[0] = 0b11111111
	thirdData[1] = 0b11111111
	thirdData[2] = 0b11111111
	thirdData[3] = 0b11111111
	thirdData[4] = 0b00111111
	assert.Equal(t, []types.FP32{{Data: firstData}, {Data: secondData}, {Data: thirdData}}, res)
}

// PRIVATE METHOD TESTS
func TestNextUnpaddedSliceSunshine(t *testing.T) {
	unpaddedData := make([]byte, 40)
	for i := range unpaddedData {
		unpaddedData[i] = byte(i)
	}
	nextSlice := getNextUnpaddedSlice(0, unpaddedData)
	expected := unpaddedData[:33]
	assert.Equal(t, expected, nextSlice)
}

func TestNextUnpaddedSliceSunshine2(t *testing.T) {
	unpaddedData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	nextSlice := getNextUnpaddedSlice(8, unpaddedData)
	assert.Equal(t, []byte{1, 2, 3, 4, 5}, nextSlice)
}

func TestNextUnpaddedSliceMiddleOffset(t *testing.T) {
	unpaddedData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	// 30/8 = 3.75
	nextSlice := getNextUnpaddedSlice(30, unpaddedData)
	assert.Equal(t, []byte{3, 4, 5, 6, 7}, nextSlice)
}

func TestNextUnpaddedSliceOverflow(t *testing.T) {
	unpaddedData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	// 35/8 = 8.125
	nextSlice := getNextUnpaddedSlice(65, unpaddedData)
	assert.Equal(t, []byte{8, 9}, nextSlice)
}

func TestNextUnpaddedSliceEmpty(t *testing.T) {
	unpaddedData := []byte{}
	nextSlice := getNextUnpaddedSlice(0, unpaddedData)
	assert.Equal(t, []byte{}, nextSlice)
}

func TestRetrieveNextFP32ByteSunshine(t *testing.T) {
	nextSlice := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

	retrievedBytes := retrieveNextFP32Byte(0, nextSlice)

	var expected [types.BytesUsedInFP32]byte
	copy(expected[:], nextSlice[:types.BytesUsedInFP32])
	assert.Equal(t, expected, retrievedBytes)
}

func TestRetrieveNextFP32ByteMiddle(t *testing.T) {
	nextSlice := make([]byte, types.BytesUsedInFP32+1)
	// Set 0 at the edge to test edge case
	nextSlice[0] = 0b11111100
	set1s(&nextSlice, 1, types.BytesUsedInFP32)
	// Set 0 at the edge to test edge case
	nextSlice[types.BytesUsedInFP32] = 0b00000011

	retrievedBytes := retrieveNextFP32Byte(2, nextSlice)

	expected := make([]byte, types.BytesUsedInFP32)
	set1s(&expected, 0, types.BytesUsedInFP32)
	var expectedFixed [types.BytesUsedInFP32]byte
	copy(expectedFixed[:], expected[:types.BytesUsedInFP32])
	assert.Equal(t, expectedFixed, retrievedBytes)
}

func TestRetrieveNextFP32ByteMiddle2(t *testing.T) {
	nextSlice := make([]byte, types.BytesUsedInFP32+1)
	// Set 0 at the edge to test edge case
	nextSlice[0] = 0b11111100
	set1s(&nextSlice, 1, types.BytesUsedInFP32)
	// Set an arbitrary middle bit to 0
	nextSlice[5] = 0b11111011
	// Set 0 at the edge to test edge case
	nextSlice[types.BytesUsedInFP32] = 0b00000011

	// Add a arbitrary product of 8 to ensure that overflow gets found correctly
	retrievedBytes := retrieveNextFP32Byte(8*100+3, nextSlice)

	expected := make([]byte, types.BytesUsedInFP32)
	set1s(&expected, 0, types.BytesUsedInFP32)
	// Check that the 0 bits are in the expected places
	expected[4] = 0b01111111
	expected[types.BytesUsedInFP32-1] = 0b01111111
	var expectedFixed [types.BytesUsedInFP32]byte
	copy(expectedFixed[:], expected[:types.BytesUsedInFP32])
	assert.Equal(t, expectedFixed, retrievedBytes)
}

func TestRetrieveNextFP32ByteOverflow(t *testing.T) {
	nextSlice := []byte{0b11111111, 0b10000000}

	// Add a arbitrary product of 8 to ensure that overflow gets found correctly
	retrievedBytes := retrieveNextFP32Byte(8*1000+4, nextSlice)

	var expected [types.BytesUsedInFP32]byte
	expected[0] = 0b00001111
	expected[1] = 0b00001000
	assert.Equal(t, expected, retrievedBytes)
}

func set1s[ARRAY types.FP32Array](input *ARRAY, startInclude int, stopExclusive int) {
	for i := startInclude; i < stopExclusive; i++ {
		(*input)[i] = 0b11111111
	}
}
