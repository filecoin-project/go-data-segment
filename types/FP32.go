package types

const BitsUsedInFP32 = 254
const BytesUsedInFP32 = 32

type FP32Array interface {
	[]byte | [BytesUsedInFP32]byte
}

type FP32 struct {
	Data [BytesUsedInFP32]byte
}
