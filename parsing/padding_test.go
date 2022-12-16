package parsing

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNextUnpaddedSliceSunshine(t *testing.T) {
	unpaddedData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	nextSlice := getNextUnpaddedSlice(0, unpaddedData)
	assert.Equal(t, []byte{0, 1, 2, 3, 4, 5}, nextSlice)
}

func TestNextUnpaddedSliceMiddleOffset(t *testing.T) {
	unpaddedData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	// 30/8 = 3.75, since we start
	nextSlice := getNextUnpaddedSlice(30, unpaddedData)
	assert.Equal(t, []byte{3, 4, 5, 6, 7}, nextSlice)
}

func TestNextUnpaddedSliceOverflow(t *testing.T) {
	unpaddedData := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	// 35/8 = 8.125, since we start
	nextSlice := getNextUnpaddedSlice(65, unpaddedData)
	assert.Equal(t, []byte{8, 9}, nextSlice)
}

func TestNextUnpaddedSliceEmpty(t *testing.T) {
	unpaddedData := []byte{}
	nextSlice := getNextUnpaddedSlice(0, unpaddedData)
	assert.Equal(t, []byte{}, nextSlice)
}
