package parsing

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNextUnpaddedSliceSunshine(t *testing.T) {
	unpaddedData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	nextSlice := getNextUnpaddedSlice(0, unpaddedData)
	assert.Equal(t, []byte{0, 1, 2, 3, 4}, nextSlice)
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
	nextSlice := []byte{0, 1, 2, 3}
	retrievedBytes := retrieveNextFP32Byte(0, nextSlice)
	assert.Equal(t, [4]byte{0, 1, 2, 3}, retrievedBytes)
}

func TestRetrieveNextFP32ByteMiddle(t *testing.T) {
	nextSlice := []byte{0b11111100, 0b11111111, 0b11111111, 0b11111111, 0b00000011}
	retrievedBytes := retrieveNextFP32Byte(2, nextSlice)
	assert.Equal(t, [4]byte{0b11111111, 0b11111111, 0b11111111, 0b11111111}, retrievedBytes)
}

func TestRetrieveNextFP32ByteMiddle2(t *testing.T) {
	nextSlice := []byte{0b11111100, 0b11111111, 0b11111011, 0b11111111, 0b00000011}
	// Add a random product of 8 to ensure that overflow gets found correctly
	retrievedBytes := retrieveNextFP32Byte(8*100+3, nextSlice)
	assert.Equal(t, [4]byte{0b11111111, 0b01111111, 0b11111111, 0b01111111}, retrievedBytes)
}

func TestRetrieveNextFP32ByteOverflow(t *testing.T) {
	nextSlice := []byte{0b11111111, 0b10000000}
	retrievedBytes := retrieveNextFP32Byte(4, nextSlice)
	assert.Equal(t, [4]byte{0b00001111, 0b00001000, 0b00000000, 0b00000000}, retrievedBytes)
}
