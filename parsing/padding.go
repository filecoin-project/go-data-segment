package parsing

import (
	"errors"
	"github.com/filecoin-project/go-data-segment/types"
)

// Pad pads a general byte array in to FP32 chunks of bytes where the topmost bits of the most significant byte are 0
func Pad(unpaddedData []byte) ([]types.FP32, error) {
	if unpaddedData == nil || len(unpaddedData) == 0 {
		return nil, errors.New("empty input")
	}
	// Compute amount of FP32 elements in the result
	amountOfFP32s := integerCeil(len(unpaddedData)*8, types.BitsUsedInFP32)
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

func Unpad(paddedData []types.FP32) ([]byte, error) {
	if paddedData == nil || len(paddedData) == 0 {
		return nil, errors.New("empty input")
	}
	// Compute amount of bytes in the result
	amountOfBytes := integerCeil(len(paddedData)*types.BitsUsedInFP32, 8)
	unpaddedData := make([]byte, amountOfBytes, amountOfBytes)
	currentPadBitIdx := 0
	for i := 0; i < len(paddedData); i++ {
		currentPaddedSlice := paddedData[i].Data
		setUnpaddedData(&unpaddedData, currentPaddedSlice, currentPadBitIdx)
		// Update currentPadBitIdx to the byte we need to start at which is 254 in
		currentPadBitIdx += types.BitsUsedInFP32
	}
	return unpaddedData, nil
}

func setUnpaddedData(unpaddedData *[]byte, FP32Data [types.BytesUsedInFP32]byte, bitOffset int) {
	bytePos := bitOffset / 8
	shift := bitOffset % 8
	for j := 0; j < types.BytesUsedInFP32-1; j++ {
		/*
			Shift the padded bytes appropriately and XO this into the current unpadded byte to ensure that the previous
			bits in this byte does not get modified, but the new bytes get contained
		*/
		(*unpaddedData)[bytePos+j] ^= FP32Data[j] << shift
		// Set the extra bits of the current padded byte, which it is no space for in the current unpadded byte, into the next byte
		if bytePos+j+1 < len(*unpaddedData) {
			(*unpaddedData)[bytePos+j+1] ^= FP32Data[j] >> (8 - shift)
		}
	}
	// Ensure the two most significant bits are 0
	mostSignificantByte := FP32Data[types.BytesUsedInFP32-1] & 0b00111111
	(*unpaddedData)[bytePos+types.BytesUsedInFP32-1] ^= mostSignificantByte << shift
	if shift > 0 {
		(*unpaddedData)[bytePos+types.BytesUsedInFP32] ^= mostSignificantByte >> (8 - shift)
	}
}

func integerCeil(x int, y int) int {
	if x == 0 {
		return 0
	}
	return 1 + ((abs(x) - 1) / abs(y))
}
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
