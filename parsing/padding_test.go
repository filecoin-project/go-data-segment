package parsing

import (
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

// INTEGRATION TESTS

func TestPadAndUnpad(t *testing.T) {
	// Soak test with random data for all possible bitlengths of Fr32
	for amount := 1001; amount < 1001+fr32.BitsNeeded+1; amount++ {
		randomBytes := make([]byte, 1001)
		rand.Seed(int64(amount))
		rand.Read(randomBytes)

		paddedData, err := Pad(&randomBytes)
		assert.Equal(t, nil, err)
		unpaddedData, err := Unpad(paddedData)
		assert.Equal(t, nil, err)
		assert.Equal(t, randomBytes, unpaddedData[:1001])
		// Check that unpadded data uses everything in the Fr32 encoding, even those bytes that have resulted in 0 bytes from encoding a weird length paddedData object
		assert.Equal(t,
			Ceil(fr32.BitsNeeded*Ceil(1001*8, fr32.BitsNeeded), 8),
			len(unpaddedData))
	}
}

// PUBLIC METHODS TESTS
func TestPadSunshine(t *testing.T) {
	size := 2*fr32.BytesNeeded + 5
	unpaddedData := make([]byte, size)
	set1s(&unpaddedData, 0, size)
	// Set 0 at the edge to test edge case
	unpaddedData[0] = 0b11111100
	// Set 0 at the edge to test edge case
	unpaddedData[size-1] = 0b00000011

	res, err := Pad(&unpaddedData)
	assert.Equal(t, nil, err)
	var firstData [fr32.BytesNeeded]byte
	set1s(&firstData, 0, fr32.BytesNeeded)
	firstData[0] = 0b11111100
	firstData[fr32.BytesNeeded-1] = 0b00111111
	var secondData [fr32.BytesNeeded]byte
	set1s(&secondData, 0, fr32.BytesNeeded)
	secondData[fr32.BytesNeeded-1] = 0b00111111
	var thirdData [fr32.BytesNeeded]byte
	thirdData[0] = 0b11111111
	thirdData[1] = 0b11111111
	thirdData[2] = 0b11111111
	thirdData[3] = 0b11111111
	thirdData[4] = 0b00111111
	assert.Equal(t, []fr32.Fr32{{Data: firstData}, {Data: secondData}, {Data: thirdData}}, res)
}

func TestUnpadSunshine(t *testing.T) {
	paddedData := make([]fr32.Fr32, 3)
	data := make([]byte, fr32.BytesNeeded)
	set1s(&data, 0, fr32.BytesNeeded)
	data[0] = 0b10101010
	data[fr32.BytesNeeded-1] = 0b00010101
	copy(paddedData[0].Data[:], data)
	copy(paddedData[1].Data[:], data)
	copy(paddedData[2].Data[:], data)

	unpaddedData, err := Unpad(paddedData)
	assert.Equal(t, nil, err)
	assert.Equal(t, unpaddedData[0], byte(0b10101010))
	assert.Equal(t, unpaddedData[1], byte(0b11111111))
	assert.Equal(t, unpaddedData[fr32.BytesNeeded-1], byte(0b10010101))
	assert.Equal(t, unpaddedData[fr32.BytesNeeded], byte(0b11101010))
	assert.Equal(t, unpaddedData[2*fr32.BytesNeeded-1], byte(0b10100101))
	assert.Equal(t, unpaddedData[2*fr32.BytesNeeded], byte(0b11111010))
	assert.Equal(t, unpaddedData[3*fr32.BytesNeeded-1], byte(0b00000001))
}

// PRIVATE METHOD TESTS
func TestGetChunkSunshine(t *testing.T) {
	unpaddedData := getMonotoneTestData(40)
	nextChunk := getChunk(0, &unpaddedData)
	expected := unpaddedData[:33]
	assert.Equal(t, expected, nextChunk)
}

func TestGetChunk2(t *testing.T) {
	unpaddedData := getMonotoneTestData(40)
	nextChunk := getChunk(8, &unpaddedData)
	expected := unpaddedData[1:34]
	assert.Equal(t, expected, nextChunk)
}

func TestGetChunkMiddleOffset(t *testing.T) {
	unpaddedData := getMonotoneTestData(40)
	// 30/8 = 3.75
	nextChunk := getChunk(30, &unpaddedData)
	expected := unpaddedData[3:36]
	assert.Equal(t, expected, nextChunk)
}

func TestGetChunkOverflow(t *testing.T) {
	unpaddedData := getMonotoneTestData(40)
	// 65/8 = 8.125
	nextChunk := getChunk(65, &unpaddedData)
	expected := unpaddedData[8:40]
	assert.Equal(t, expected, nextChunk)
}

func TestGetChunkEmpty(t *testing.T) {
	unpaddedData := []byte{}
	nextChunk := getChunk(0, &unpaddedData)
	assert.Equal(t, []byte{}, nextChunk)
}

func TestShiftChunkSunshine(t *testing.T) {
	nextChunk := getMonotoneTestData(32)

	retrievedBytes := shiftChunk(0, nextChunk)

	assert.Equal(t, []byte(nextChunk), retrievedBytes[:])
}

func TestShiftChunkMiddle(t *testing.T) {
	nextChunk := make([]byte, fr32.BytesNeeded+1)
	// Set 0 at the edge to test edge case
	nextChunk[0] = 0b11111100
	set1s(&nextChunk, 1, fr32.BytesNeeded)
	// Set 0 at the edge to test edge case
	nextChunk[fr32.BytesNeeded] = 0b00000011

	retrievedBytes := shiftChunk(2, nextChunk)

	expected := make([]byte, fr32.BytesNeeded)
	set1s(&expected, 0, fr32.BytesNeeded)
	expected[31] &= 0b00111111
	assert.Equal(t, expected, retrievedBytes[:])
}

func TestShiftChunkMiddle2(t *testing.T) {
	nextChunk := make([]byte, fr32.BytesNeeded+1)
	// Set 0 at the edge to test edge case
	nextChunk[0] = 0b11111000
	set1s(&nextChunk, 1, fr32.BytesNeeded)
	// Set an arbitrary middle bit to 0
	nextChunk[5] = 0b11111011
	// Set 0 at the edge to test edge case
	nextChunk[fr32.BytesNeeded] = 0b11111110

	// Add an arbitrary product of 8 to ensure that overflow gets found correctly
	retrievedBytes := shiftChunk(8*100+3, nextChunk)

	expected := make([]byte, fr32.BytesNeeded)
	set1s(&expected, 0, fr32.BytesNeeded)
	// Check that the 0 bits are in the expected places
	expected[4] = 0b01111111
	expected[fr32.BytesNeeded-1] = 0b00011111
	assert.Equal(t, expected, retrievedBytes[:])
}

func TestShiftChunkOverflow(t *testing.T) {
	nextChunk := []byte{0b11111111, 0b10000000}

	// Add an arbitrary product of 8 to ensure that overflow gets found correctly
	retrievedBytes := shiftChunk(8*1000+4, nextChunk)

	var expected [fr32.BytesNeeded]byte
	expected[0] = 0b00001111
	expected[1] = 0b00001000
	assert.Equal(t, expected, retrievedBytes)
}

func TestSetChunkSunshine(t *testing.T) {
	unpaddedData := make([]byte, 100)
	var paddedData [fr32.BytesNeeded]byte
	set1s(&paddedData, 0, fr32.BytesNeeded)
	paddedData[0] = 0b11111110
	// Notice the two most significant bits are 1 and should be ignored
	paddedData[fr32.BytesNeeded-1] = 0b11011111

	setChunk(&unpaddedData, paddedData, 8)

	for i := 0; i < fr32.BytesNeeded-1; i++ {
		assert.Equal(t, unpaddedData[i+1], paddedData[i])
	}
	assert.Equal(t, byte(0b00011111), unpaddedData[fr32.BytesNeeded])
}

func TestSetChunkMiddle(t *testing.T) {
	unpaddedData := make([]byte, 100)
	var paddedData [fr32.BytesNeeded]byte
	set1s(&paddedData, 0, fr32.BytesNeeded)
	paddedData[0] = 0b11111101
	// Notice the two most significant bits are 1 and should be ignored
	paddedData[fr32.BytesNeeded-1] = 0b00111111

	setChunk(&unpaddedData, paddedData, 19)

	expected := make([]byte, 100)
	set1s(&expected, 19/8, 19/8+fr32.BytesNeeded)
	expected[19/8] = 0b11101000
	expected[19/8+fr32.BytesNeeded] = 0b00000001
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
	var input [0]fr32.Fr32
	_, err := Unpad(input[:])
	assert.NotNil(t, err)
}

/**
 *	HELPER FUNCTIONS
 */

func set1s[ARRAY fr32.Fr32Array](input *ARRAY, startIncludeByte int, stopExclusiveByte int) {
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
