package parsing

import (
	"github.com/filecoin-project/go-data-segment/types"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

// INTEGRATION TESTS

func TestPadAndUnpad(t *testing.T) {
	// Soak test with random data for all possible bitlengths of FP32
	for testAmount := 1001; testAmount < 1001+types.BitsUsedInFP32+1; testAmount++ {
		randomBytes := make([]byte, 1001)
		rand.Seed(int64(testAmount))
		rand.Read(randomBytes)

		paddedData, err := Pad(&randomBytes)
		assert.Equal(t, nil, err)
		unpaddedData, err := Unpad(paddedData)
		assert.Equal(t, nil, err)
		assert.Equal(t, randomBytes, unpaddedData[:1001])
		// Check that unpadded data uses everything in the FP32 encoding, even those bytes that have resulted in 0 bytes from encoding a weird length paddedData object
		assert.Equal(t,
			IntegerCeil(types.BitsUsedInFP32*IntegerCeil(1001*8, types.BitsUsedInFP32), 8),
			len(unpaddedData))
	}
}

// PUBLIC METHODS TESTS
func TestPadSunshine(t *testing.T) {
	size := 2*types.BytesUsedInFP32 + 5
	unpaddedData := make([]byte, size)
	set1s(&unpaddedData, 0, size)
	// Set 0 at the edge to test edge case
	unpaddedData[0] = 0b11111100
	// Set 0 at the edge to test edge case
	unpaddedData[size-1] = 0b00000011

	res, err := Pad(&unpaddedData)
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

func TestUnpadSunshine(t *testing.T) {
	paddedData := make([]types.FP32, 3)
	data := make([]byte, types.BytesUsedInFP32)
	set1s(&data, 0, types.BytesUsedInFP32)
	data[0] = 0b10101010
	data[types.BytesUsedInFP32-1] = 0b00010101
	copy(paddedData[0].Data[:], data)
	copy(paddedData[1].Data[:], data)
	copy(paddedData[2].Data[:], data)

	unpaddedData, err := Unpad(paddedData)
	assert.Equal(t, nil, err)
	assert.Equal(t, unpaddedData[0], byte(0b10101010))
	assert.Equal(t, unpaddedData[1], byte(0b11111111))
	assert.Equal(t, unpaddedData[types.BytesUsedInFP32-1], byte(0b10010101))
	assert.Equal(t, unpaddedData[types.BytesUsedInFP32], byte(0b11101010))
	assert.Equal(t, unpaddedData[2*types.BytesUsedInFP32-1], byte(0b10100101))
	assert.Equal(t, unpaddedData[2*types.BytesUsedInFP32], byte(0b11111010))
	assert.Equal(t, unpaddedData[3*types.BytesUsedInFP32-1], byte(0b00000001))
}

// PRIVATE METHOD TESTS
func TestNextUnpaddedSliceSunshine(t *testing.T) {
	unpaddedData := getMonotoneTestData(40)
	nextSlice := getNextUnpaddedSlice(0, &unpaddedData)
	expected := unpaddedData[:33]
	assert.Equal(t, expected, nextSlice)
}

func TestNextUnpaddedSliceSunshine2(t *testing.T) {
	unpaddedData := getMonotoneTestData(40)
	nextSlice := getNextUnpaddedSlice(8, &unpaddedData)
	expected := unpaddedData[1:34]
	assert.Equal(t, expected, nextSlice)
}

func TestNextUnpaddedSliceMiddleOffset(t *testing.T) {
	unpaddedData := getMonotoneTestData(40)
	// 30/8 = 3.75
	nextSlice := getNextUnpaddedSlice(30, &unpaddedData)
	expected := unpaddedData[3:36]
	assert.Equal(t, expected, nextSlice)
}

func TestNextUnpaddedSliceOverflow(t *testing.T) {
	unpaddedData := getMonotoneTestData(40)
	// 65/8 = 8.125
	nextSlice := getNextUnpaddedSlice(65, &unpaddedData)
	expected := unpaddedData[8:40]
	assert.Equal(t, expected, nextSlice)
}

func TestNextUnpaddedSliceEmpty(t *testing.T) {
	unpaddedData := []byte{}
	nextSlice := getNextUnpaddedSlice(0, &unpaddedData)
	assert.Equal(t, []byte{}, nextSlice)
}

func TestRetrieveNextFP32ByteSunshine(t *testing.T) {
	nextSlice := getMonotoneTestData(32)

	retrievedBytes := retrieveNextFP32(0, nextSlice)

	assert.Equal(t, []byte(nextSlice), retrievedBytes[:])
}

func TestRetrieveNextFP32ByteMiddle(t *testing.T) {
	nextSlice := make([]byte, types.BytesUsedInFP32+1)
	// Set 0 at the edge to test edge case
	nextSlice[0] = 0b11111100
	set1s(&nextSlice, 1, types.BytesUsedInFP32)
	// Set 0 at the edge to test edge case
	nextSlice[types.BytesUsedInFP32] = 0b00000011

	retrievedBytes := retrieveNextFP32(2, nextSlice)

	expected := make([]byte, types.BytesUsedInFP32)
	set1s(&expected, 0, types.BytesUsedInFP32)
	expected[31] &= 0b00111111
	assert.Equal(t, expected, retrievedBytes[:])
}

func TestRetrieveNextFP32ByteMiddle2(t *testing.T) {
	nextSlice := make([]byte, types.BytesUsedInFP32+1)
	// Set 0 at the edge to test edge case
	nextSlice[0] = 0b11111000
	set1s(&nextSlice, 1, types.BytesUsedInFP32)
	// Set an arbitrary middle bit to 0
	nextSlice[5] = 0b11111011
	// Set 0 at the edge to test edge case
	nextSlice[types.BytesUsedInFP32] = 0b11111110

	// Add an arbitrary product of 8 to ensure that overflow gets found correctly
	retrievedBytes := retrieveNextFP32(8*100+3, nextSlice)

	expected := make([]byte, types.BytesUsedInFP32)
	set1s(&expected, 0, types.BytesUsedInFP32)
	// Check that the 0 bits are in the expected places
	expected[4] = 0b01111111
	expected[types.BytesUsedInFP32-1] = 0b00011111
	assert.Equal(t, expected, retrievedBytes[:])
}

func TestRetrieveNextFP32ByteOverflow(t *testing.T) {
	nextSlice := []byte{0b11111111, 0b10000000}

	// Add an arbitrary product of 8 to ensure that overflow gets found correctly
	retrievedBytes := retrieveNextFP32(8*1000+4, nextSlice)

	var expected [types.BytesUsedInFP32]byte
	expected[0] = 0b00001111
	expected[1] = 0b00001000
	assert.Equal(t, expected, retrievedBytes)
}

func TestSetUnpaddedDataSunshine(t *testing.T) {
	unpaddedData := make([]byte, 100)
	var paddedData [types.BytesUsedInFP32]byte
	set1s(&paddedData, 0, types.BytesUsedInFP32)
	paddedData[0] = 0b11111110
	// Notice the two most significant bits are 1 and should be ignored
	paddedData[types.BytesUsedInFP32-1] = 0b11011111

	setUnpaddedData(&unpaddedData, paddedData, 8)

	for i := 0; i < types.BytesUsedInFP32-1; i++ {
		assert.Equal(t, unpaddedData[i+1], paddedData[i])
	}
	assert.Equal(t, byte(0b00011111), unpaddedData[types.BytesUsedInFP32])
}

func TestSetUnpaddedDataMiddle(t *testing.T) {
	unpaddedData := make([]byte, 100)
	var paddedData [types.BytesUsedInFP32]byte
	set1s(&paddedData, 0, types.BytesUsedInFP32)
	paddedData[0] = 0b11111101
	// Notice the two most significant bits are 1 and should be ignored
	paddedData[types.BytesUsedInFP32-1] = 0b00111111

	setUnpaddedData(&unpaddedData, paddedData, 19)

	expected := make([]byte, 100)
	set1s(&expected, 19/8, 19/8+types.BytesUsedInFP32)
	expected[19/8] = 0b11101000
	expected[19/8+types.BytesUsedInFP32] = 0b00000001
	assert.Equal(t, expected, unpaddedData)
}

/**
 *  NEGATIVE TESTS
 */

func TestNilInputPad(t *testing.T) {
	_, err := Pad(nil)
	assert.NotNil(t, err)
}

func TestNilInputUnpad(t *testing.T) {
	_, err := Unpad(nil)
	assert.NotNil(t, err)
}

func TestEmptyInputPad(t *testing.T) {
	input := make([]byte, 0)
	_, err := Pad(&input)
	assert.NotNil(t, err)
}

func TestEmptyInputUnpad(t *testing.T) {
	var input [0]types.FP32
	_, err := Unpad(input[:])
	assert.NotNil(t, err)
}

/**
 *	HELPER FUNCTIONS
 */

func set1s[ARRAY types.FP32Array](input *ARRAY, startIncludeByte int, stopExclusiveByte int) {
	for i := startIncludeByte; i < stopExclusiveByte; i++ {
		(*input)[i] = 0b11111111
	}
}

func getMonotoneTestData(amount int) []byte {
	unpaddedData := make([]byte, amount)
	for i := range unpaddedData {
		unpaddedData[i] = byte(i)
	}
	return unpaddedData
}
