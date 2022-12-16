package parsing

import (
	"errors"
	"github.com/filecoin-project/go-data-segment/types"
	"math"
)

// Pad pads a general byte array in to FP32 chunks of bytes where the topmost bits of the most significant byte are 0
func Pad(unpaddedData []byte) ([]types.FP32, error) {
	if unpaddedData == nil || len(unpaddedData) == 0 {
		return nil, errors.New("empty input")
	}
	// Compute amount of FP32 elements in the result
	amountOfFP32s := int(math.Ceil(float64(len(unpaddedData)*8) / float64(types.BitsUsedInFP32)))
	paddedData := make([]types.FP32, amountOfFP32s, amountOfFP32s)
	currentPadBitIdx := 0
	for i := 0; i < amountOfFP32s; i++ {
		currentUnpaddedSlice := getNextUnpaddedSlice(currentPadBitIdx, unpaddedData)
		paddedData[i] = types.FP32{Data: retrieveNextFP32Byte(currentPadBitIdx, currentUnpaddedSlice)}
		// Update currentPadBitIdx to the byte we need to start at which is 254 in
		currentPadBitIdx += types.BitsUsedInFP32
	}
	return paddedData, nil
}

// Return a slice containing the next segment of unpadded data (without copying data), it will be a slice of either 32 or 33 bytes
func getNextUnpaddedSlice(currentPadBitIdx int, unpaddedData []byte) []byte {
	var upperIdx int
	// Find the largest byte we can access in the unpadded array, in case we are in the end of the array
	if (currentPadBitIdx/8)+types.BytesUsedInFP32+1 < len(unpaddedData) {
		upperIdx = (currentPadBitIdx / 8) + types.BytesUsedInFP32 + 1
	} else {
		upperIdx = len(unpaddedData)
	}
	return unpaddedData[currentPadBitIdx/8 : upperIdx]
}

// Takes an arbitrary bit index, currentPadBitIdx and a slice of sufficient unpadded bytes to construct an FP32
// Computes the bit offset from currentPadBitIdx and extracts the 254 bits currentUnpaddedSlice and return these in a 32 byte list
func retrieveNextFP32Byte(currentPadBitIdx int, currentUnpaddedSlice []byte) [types.BytesUsedInFP32]byte {
	var paddedBytes [types.BytesUsedInFP32]byte
	shift := currentPadBitIdx % 8
	for j := 0; j < types.BytesUsedInFP32; j++ {
		// Check if the next bytes are there
		if j < len(currentUnpaddedSlice) {
			paddedBytes[j] = currentUnpaddedSlice[j] >> shift
		}
		// XOR in the bits from the next byte if needed (if it is there)
		if j+1 < len(currentUnpaddedSlice) {
			paddedBytes[j] ^= currentUnpaddedSlice[j+1] << (8 - shift)
		}
	}
	// Ensure the upper bits are set to 0
	paddedBytes[types.BytesUsedInFP32-1] &= 0b00111111
	return paddedBytes
}
