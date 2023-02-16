package merkletree

import (
	_ "embed"

	"github.com/filecoin-project/go-data-segment/util"
	xerrors "golang.org/x/xerrors"
)

//go:embed zerocomm.bin
var zeroComms []byte

// simple access by level, only levels between 0 and 64 inclusive are avaliable otherwise panics
func ZeroCommitmentForLevel(lvl int) Node {
	return *(*Node)(zeroComms[32*lvl : 32*(lvl+1)])
}

func ZeroCommitmentForSize(size uint64) (Node, error) {
	lvl := util.Log2Ceil(size / digestBytes)
	if lvl*32 >= len(zeroComms) {
		return Node{}, xerrors.Errorf("zero commimtents for size %d are not supported", size)
	}
	return ZeroCommitmentForLevel(lvl), nil
}
