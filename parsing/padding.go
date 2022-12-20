package parsing

import (
	"errors"
	"github.com/filecoin-project/go-data-segment/fr32"
)

// Pad pads a general byte array in to Fr32 chunks of bytes where the topmost bits of the most significant byte are 0
func Pad(unpaddedData *[]byte) ([]fr32.Fr32, error) {
	if unpaddedData == nil || len(*unpaddedData) == 0 {
		return nil, errors.New("empty input")
	}
	// Compute amount of Fr32 elements in the result
	chunkCount := Ceil(len(*unpaddedData)*8, fr32.BitsNeeded)
	paddedData := make([]fr32.Fr32, chunkCount, chunkCount)
	bitIdx := 0
	for i := 0; i < chunkCount; i++ {
		unpaddedChunk := getChunk(bitIdx, unpaddedData)
		paddedData[i] = fr32.Fr32{Data: shiftChunk(bitIdx, unpaddedChunk)}
		// Update bitIdx to the byte we need to start at which is 254 in
		bitIdx += fr32.BitsNeeded
	}
	return paddedData, nil
}

// Return a chunk containing the next segment of unpadded data (without copying data), it will be a chunk of either 32 or 33 bytes
func getChunk(bitIdx int, unpaddedData *[]byte) []byte {
	var upperIdx int
	// Find the largest byte we can access in the unpadded array, in case we are in the end of the array
	if (bitIdx/8)+fr32.BytesNeeded+1 < len(*unpaddedData) {
		upperIdx = (bitIdx / 8) + fr32.BytesNeeded + 1
	} else {
		upperIdx = len(*unpaddedData)
	}
	return (*unpaddedData)[bitIdx/8 : upperIdx]
}

// Takes an arbitrary bit index, bitIdx and a chunk of sufficient unpadded bytes to construct a Fr32 chunk
// Computes the bit offset from bitIdx % 8 and extracts the 254 bits unpaddedChunk and return these in a 32 byte list
func shiftChunk(bitIdx int, unpaddedChunk []byte) [fr32.BytesNeeded]byte {
	var paddedBytes [fr32.BytesNeeded]byte
	shift := bitIdx % 8
	for j := 0; j < fr32.BytesNeeded; j++ {
		// Check if the next bytes are there
		if j < len(unpaddedChunk) {
			paddedBytes[j] = unpaddedChunk[j] >> shift
		}
		// XOR in the bits from the next byte if needed (if it is there)
		if j+1 < len(unpaddedChunk) {
			paddedBytes[j] ^= unpaddedChunk[j+1] << (8 - shift)
		}
	}
	// Ensure the upper bits are set to 0
	paddedBytes[fr32.BytesNeeded-1] &= 0b00111111
	return paddedBytes
}

// Unpad a list of Fr32 padded elements into a contiguous byte array
func Unpad(paddedData []fr32.Fr32) ([]byte, error) {
	if paddedData == nil || len(paddedData) == 0 {
		return nil, errors.New("empty input")
	}
	// Compute amount of bytes in the result
	bytes := Ceil(len(paddedData)*fr32.BitsNeeded, 8)
	unpaddedData := make([]byte, bytes, bytes)
	bitIdx := 0
	for i := 0; i < len(paddedData); i++ {
		chunk := paddedData[i].Data
		setChunk(&unpaddedData, chunk, bitIdx)
		// Update bitIdx to the byte we need to start at which is 254 in
		bitIdx += fr32.BitsNeeded
	}
	return unpaddedData, nil
}

// setChunk sets the bits of fr32Data in the byte array unpaddedData, starting from bitOffset
func setChunk(unpaddedData *[]byte, fr32Data [fr32.BytesNeeded]byte, bitOffset int) {
	bytePos := bitOffset / 8
	shift := bitOffset % 8
	for j := 0; j < fr32.BytesNeeded-1; j++ {
		/*
			Shift the padded bytes appropriately and XOR this into the current unpadded byte to ensure that the previous
			bits in this byte does not get modified, but the new bytes get contained
		*/
		(*unpaddedData)[bytePos+j] ^= fr32Data[j] << shift
		// Set the extra bits of the current padded byte, which it is no space for in the current unpadded byte, into the next byte
		if bytePos+j+1 < len(*unpaddedData) {
			(*unpaddedData)[bytePos+j+1] ^= fr32Data[j] >> (8 - shift)
		}
	}
	// Ensure the two most significant bits are 0 of the last byte
	lastByte := fr32Data[fr32.BytesNeeded-1] & 0b00111111
	(*unpaddedData)[bytePos+fr32.BytesNeeded-1] ^= lastByte << shift
	// Check if the shift indicates that there are more bytes to process and add to the next byte
	if shift > 2 {
		(*unpaddedData)[bytePos+fr32.BytesNeeded] ^= lastByte >> (8 - shift)
	}
}

// Ceil computes the ceiling of x/y for x, y being integers
func Ceil(x int, y int) int {
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
