package merkletree

import (
	"os"
	"testing"
)

func TestGenerateZeroCommTable(t *testing.T) {
	if os.Getenv("ZEROCCOMM_REGEN") == "" {
		t.SkipNow()
	}
	maxD := 64
	zeroComms := make([]Node, maxD)
	for i := 1; i < maxD; i++ {
		zeroComms[i] = *computeNode(&zeroComms[i-1], &zeroComms[i-1])
	}
	f, err := os.Create("zerocomm.bin")
	if err != nil {
		panic(err)
	}

	for _, z := range zeroComms {
		_, err := f.Write(z[:])
		if err != nil {
			panic(err)
		}
	}
	err = f.Close()
	if err != nil {
		panic(err)
	}
}
