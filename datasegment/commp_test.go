package datasegment

import (
	"bytes"
	"testing"

	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/stretchr/testify/assert"
)

func TestLightCommP2Cid(t *testing.T) {
	node := [32]byte{}
	for i := range node {
		node[i] = byte(i)
	}
	c1, err := commcid.PieceCommitmentV1ToCID(node[:])
	assert.NoError(t, err)
	c2, err := lightCommP2Cid(node)
	assert.NoError(t, err)

	assert.Equal(t, c1, c2)
}

func TestLightCid2CommP(t *testing.T) {
	node := [32]byte{}
	for i := range node {
		node[i] = byte(i)
	}
	c, err := commcid.PieceCommitmentV1ToCID(node[:])
	assert.NoError(t, err)
	n1, err := lightCid2CommP(c)
	assert.NoError(t, err)

	assert.Equal(t, node, n1)

	c2, err := commcid.ReplicaCommitmentV1ToCID(node[:])
	assert.NoError(t, err)
	_, err = lightCid2CommP(c2)
	assert.Error(t, err)
}

func FuzzLightCid2CommP(f *testing.F) {
	node := [32]byte{}
	for i := range node {
		node[i] = byte(i)
	}
	c, err := commcid.PieceCommitmentV1ToCID(node[:])
	assert.NoError(f, err)
	f.Add(c.Bytes())

	c2, err := commcid.ReplicaCommitmentV1ToCID(node[:])
	assert.NoError(f, err)
	f.Add(c2.Bytes())

	f.Fuzz(func(t *testing.T, b []byte) {
		cb := bytesWrapper(b)
		n, err := lightCid2CommP(cb)
		if err == nil && !bytes.Equal(b[len(cidCommPHeader):], n[:]) {
			t.Fatal("wrong node content")
		}
	})
}

type bytesWrapper []byte

func (b bytesWrapper) Bytes() []byte {
	return []byte(b)
}
