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
func TestInclusionSerialization(t *testing.T) {
	root := merkletree.Node{}
	commDA := fr32.Fr32{}
	proofSub := merkletree.NewDummyProof(4, 5, &root)
	proofDs := merkletree.NewDummyProof(6, 4233, &root)
	structure := Inclusion{CommDA: commDA, Size: 1234, ProofSubtree: proofSub, ProofDs: proofDs}
	encoded, errEnc := SerializeInclusion(structure)
	assert.Nil(t, errEnc)
	assert.NotNil(t, encoded)
	decoded, errDec := DeserializeInclusion(encoded)
	assert.Nil(t, errDec)
	assert.NotNil(t, decoded)
	assert.Equal(t, commDA, decoded.CommDA)
	assert.Equal(t, proofSub.Path(), decoded.ProofSubtree.Path())
	assert.Equal(t, proofSub.Level(), decoded.ProofSubtree.Level())
	assert.Equal(t, proofSub.Index(), decoded.ProofSubtree.Index())
	assert.Equal(t, proofDs.Path(), decoded.ProofDs.Path())
	assert.Equal(t, proofDs.Level(), decoded.ProofDs.Level())
	assert.Equal(t, proofDs.Index(), decoded.ProofDs.Index())
	assert.Equal(t, 1234, decoded.Size)
}

func TestInclusionSerializationIntegration(t *testing.T) {
	leafs := [][]byte{{0x01, 0x02}, {0x03}, {0x04}, {0x05}, {0x06}}
	tree, err := merkletree.GrowTree(leafs)
	assert.Nil(t, err)
	digest := *merkletree.TruncatedHash(leafs[3])
	commDA := fr32.Fr32{Data: digest.Data}
	proofSub, err := tree.ConstructProof(1, 1)
	assert.Nil(t, err)
	proofDs, err := tree.ConstructProof(tree.Depth()-1, 3)
	assert.Nil(t, err)
	structure := Inclusion{CommDA: commDA, Size: 1234, ProofSubtree: proofSub, ProofDs: proofDs}
	encoded, errEnc := SerializeInclusion(structure)
	assert.Nil(t, errEnc)
	assert.NotNil(t, encoded)
	decoded, errDec := DeserializeInclusion(encoded)
	assert.Nil(t, errDec)
	assert.NotNil(t, decoded)
	assert.Equal(t, commDA, decoded.CommDA)
	assert.True(t, reflect.DeepEqual(proofSub, decoded.ProofSubtree))
	assert.True(t, reflect.DeepEqual(proofDs, decoded.ProofDs))
	assert.Equal(t, proofSub.Path(), decoded.ProofSubtree.Path())
	assert.Equal(t, 1234, decoded.Size)
}

// NEGATIVE TESTS
func TestNegativeInclusionSerializationSize(t *testing.T) {
	inc := Inclusion{
		CommDA:       fr32.Fr32{},
		Size:         0,
		ProofSubtree: nil,
		ProofDs:      nil,
	}
	serialized, err := SerializeInclusion(inc)
	assert.NotNil(t, err)
	assert.Nil(t, serialized)
}

func TestNegativeInclusionDeserializeProofEmpty(t *testing.T) {
	_, err := DeserializeInclusion(nil)
	assert.NotNil(t, err)
	_, err = DeserializeInclusion([]byte{})
	assert.NotNil(t, err)
}

func TestNegativeInclusionDeserializeProofSize(t *testing.T) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint64(0))
	assert.Nil(t, err)
	proof, size, err := deserializeProof(buf.Bytes())
	assert.Nil(t, proof)
	assert.Equal(t, -1, size)
	assert.NotNil(t, err)
}

func TestNegativeInclusionDeserializeProofSize2(t *testing.T) {
	encoded := make([]byte, minSizeInclusion)
	_, err := DeserializeInclusion(encoded)
	assert.NotNil(t, err)
}
