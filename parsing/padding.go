package parsing

import (
	"errors"
	"github.com/filecoin-project/go-data-segment/types"
	"math"
)

// Pad pads a general byte array in to FP32 chunks of 4 bytes where the topmost bits of the most significant byte are 0
func Pad(unpaddedData []byte) ([]types.FP32, error) {
	if unpaddedData == nil || len(unpaddedData) == 0 {
		return nil, errors.New("empty input")
	}
	// Compute amount of FP32 elements in the result
	amountOfFP32s := int(math.Ceil(float64(len(unpaddedData)*8) / float64(254)))
	paddedData := make([]types.FP32, amountOfFP32s, amountOfFP32s)
	currentPadBitIdx := 0
	for i := 0; i < amountOfFP32s; i++ {
		currentUnpaddedSlice := getNextUnpaddedSlice(currentPadBitIdx, unpaddedData)
		var paddedBytes [4]byte
		shift := currentPadBitIdx % 8
		for j := 0; j < 4; j++ {
			paddedBytes[j] = currentUnpaddedSlice[j] << shift
			paddedBytes[j] ^= currentUnpaddedSlice[j+1] >> (8 - shift)
		}
		paddedData[i] = types.FP32{Data: paddedBytes}
		// Update currentPadBitIdx to the byte nwe need to start at which is 254 in
		currentPadBitIdx += types.BitsUsedInFP32
	}
	return paddedData, nil
}

// Return a slice containing the next segment of unpadded data
func getNextUnpaddedSlice(currentPadBitIdx int, unpaddedData []byte) []byte {
	var upperIdx int
	// Find the largest byte we can access in the unpadded array, in case we are in the end of the array
	if (currentPadBitIdx/8)+5 < len(unpaddedData) {
		upperIdx = (currentPadBitIdx / 8) + 5
	} else {
		upperIdx = len(unpaddedData)
	}
	return unpaddedData[currentPadBitIdx/8 : upperIdx]
}
