package datasegment

import (
	"bytes"

	"github.com/filecoin-project/go-data-segment/merkletree"
	cid "github.com/ipfs/go-cid"
	xerrors "golang.org/x/xerrors"
)

var cidCommPHeader = []byte{0x1, 0x81, 0xe2, 0x3, 0x92, 0x20, 0x20}

type toBytes interface {
	Bytes() []byte
}

func lightCid2CommP(c toBytes) ([32]byte, error) {
	cb := c.Bytes()

	if len(cb) != merkletree.NodeSize+len(cidCommPHeader) {
		return [32]byte{}, xerrors.Errorf("wrong length of CID: %d (actual) != %d (expected)",
			len(cb), merkletree.NodeSize+len(cidCommPHeader))
	}

	header, rest := cb[:len(cidCommPHeader)], cb[len(cidCommPHeader):]
	if !bytes.Equal(cidCommPHeader, header) {
		return [32]byte{}, xerrors.Errorf("wrong content of CID header")
	}
	res := *(*[32]byte)(rest)

	return res, nil
}

func lightCommP2Cid(commp [32]byte) (cid.Cid, error) {
	// this is all that needs to be done to get valid Cid
	cb := append(cidCommPHeader, commp[:]...)

	return cid.Cast(cb) // Cast performs checks which we know will succeed
}
