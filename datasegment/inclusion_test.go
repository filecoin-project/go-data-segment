package datasegment

import (
	"bytes"
	"encoding/binary"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

// PUBLIC METHODS
func TestSerialization(t *testing.T) {
	root := merkletree.Node{}
	commDA := fr32.Fr32{}
	proofSub := merkletree.NewDummyProof(4, 5, &root)
	proofDs := merkletree.NewDummyProof(6, 4233, &root)
	structure := Structure{commDA: commDA, size: 1234, proofSubtree: proofSub, proofDs: proofDs}
	encoded, errEnc := Serialize(structure)
	assert.Nil(t, errEnc)
	assert.NotNil(t, encoded)
	decoded, errDec := Deserialize(encoded)
	assert.Nil(t, errDec)
	assert.NotNil(t, decoded)
	assert.Equal(t, commDA, decoded.commDA)
	assert.Equal(t, proofSub.Path(), decoded.proofSubtree.Path())
	assert.Equal(t, proofSub.Level(), decoded.proofSubtree.Level())
	assert.Equal(t, proofSub.Index(), decoded.proofSubtree.Index())
	assert.Equal(t, proofDs.Path(), decoded.proofDs.Path())
	assert.Equal(t, proofDs.Level(), decoded.proofDs.Level())
	assert.Equal(t, proofDs.Index(), decoded.proofDs.Index())
	assert.Equal(t, 1234, decoded.size)
}

func TestSerializationIntegration(t *testing.T) {
	leafs := [][]byte{{0x01, 0x02}, {0x03}, {0x04}, {0x05}, {0x06}}
	tree, err := merkletree.GrowTree(leafs)
	assert.Nil(t, err)
	digest := *merkletree.TruncatedHash(leafs[3])
	commDA := fr32.Fr32{Data: digest.Data}
	proofSub, err := tree.ConstructProof(1, 1)
	assert.Nil(t, err)
	proofDs, err := tree.ConstructProof(tree.Depth()-1, 3)
	assert.Nil(t, err)
	structure := Structure{commDA: commDA, size: 1234, proofSubtree: proofSub, proofDs: proofDs}
	encoded, errEnc := Serialize(structure)
	assert.Nil(t, errEnc)
	assert.NotNil(t, encoded)
	decoded, errDec := Deserialize(encoded)
	assert.Nil(t, errDec)
	assert.NotNil(t, decoded)
	assert.Equal(t, commDA, decoded.commDA)
	assert.True(t, reflect.DeepEqual(proofSub, decoded.proofSubtree))
	assert.True(t, reflect.DeepEqual(proofDs, decoded.proofDs))
	assert.Equal(t, proofSub.Path(), decoded.proofSubtree.Path())
	assert.Equal(t, 1234, decoded.size)
}

func TestNegativeSerializationSize(t *testing.T) {
	inc := Structure{
		commDA:       fr32.Fr32{},
		size:         0,
		proofSubtree: nil,
		proofDs:      nil,
	}
	serialized, err := Serialize(inc)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
}

func TestNegativeDeserializeProofEmpty(t *testing.T) {
	_, err := Deserialize(nil)
	assert.NotNil(t, err)
	_, err = Deserialize([]byte{})
	assert.NotNil(t, err)
}

func TestNegativeDeserializeProofSize(t *testing.T) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint64(0))
	assert.Nil(t, err)
	proof, size, err := deserializeProof(buf.Bytes())
	assert.Nil(t, proof)
	assert.Equal(t, -1, size)
	assert.NotNil(t, err)
}

func TestNegativeDeserializeProofSize2(t *testing.T) {
	encoded := make([]byte, fr32.BytesNeeded+5*BytesInInt)
	_, err := Deserialize(encoded)
	assert.NotNil(t, err)
}
