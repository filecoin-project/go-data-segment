package fr32

const BitsNeeded = 254
const BytesNeeded = 32

type Fr32Array interface {
	[]byte | [BytesNeeded]byte
}

type Fr32 struct {
	Data [BytesNeeded]byte
}
