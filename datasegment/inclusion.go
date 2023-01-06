package datasegment

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"log"
)

// BytesInInt represents the amount of bytes used to encode an int
const BytesInInt int = 64 / 8

// 3 integers includes the IndexSize of the aggregator's data and the size of the two Merkle proofs
const minSizeInclusion int = fr32.BytesNeeded + 3*BytesInInt

type Inclusion struct {
	CommDA fr32.Fr32
	// Size of the aggregator's data in bytes
	Size int
	// ProofSubtree proof of inclusion of the client's data in the data aggregator's Merkle tree (includes position information)
	ProofSubtree merkletree.MerkleProof
	// ProofDs leaf inclusion proof (includes position information)
	ProofDs merkletree.MerkleProof
}

// SerializeInclusion encodes a data segment Inclusion into a byte array
func SerializeInclusion(inclusion Inclusion) ([]byte, error) {
	if !validateInclusionStructure(inclusion) {
		return nil, errors.New("the structure is not valid")
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, inclusion.CommDA)
	if err != nil {
		log.Println("could not write the commitment")
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(inclusion.Size))
	if err != nil {
		log.Println("could not write IndexSize")
		return nil, err
	}
	err = serializeProof(buf, inclusion.ProofSubtree)
	if err != nil {
		return nil, err
	}
	err = serializeProof(buf, inclusion.ProofDs)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func validateInclusionStructure(structure Inclusion) bool {
	if structure.Size <= 0 {
		log.Println("size of aggregator's data must be positive")
		return false
	}
	return true
}

// DeserializeInclusion decodes a byte array into a data segment Inclusion
func DeserializeInclusion(encoded []byte) (Inclusion, error) {
	if encoded == nil || len(encoded) < minSizeInclusion {
		log.Println("no data segment inclusion encoded")
		return Inclusion{}, errors.New("no data segment inclusion encoded")
	}
	ctr := 0
	commDA := (*[fr32.BytesNeeded]byte)(encoded[ctr:fr32.BytesNeeded])
	ctr += fr32.BytesNeeded
	size := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	if size <= 0 {
		log.Println("IndexSize of aggregator's data must be positive")
		return Inclusion{}, errors.New("size of aggregator's data must be positive")
	}
	subtreeProof, subtreeProofSize, err := deserializeProof(encoded[ctr:])
	if err != nil || subtreeProofSize <= 0 {
		return Inclusion{}, errors.New("no data segment inclusion encoded")
	}
	ctr += subtreeProofSize + BytesInInt
	proofDs, dsProofSize, err := deserializeProof(encoded[ctr:])
	if err != nil || dsProofSize <= 0 {
		return Inclusion{}, errors.New("no data segment inclusion encoded")
	}
	inclusion := Inclusion{
		CommDA:       fr32.Fr32{Data: *commDA},
		Size:         size,
		ProofSubtree: subtreeProof,
		ProofDs:      proofDs,
	}
	if !validateInclusionStructure(inclusion) {
		return Inclusion{}, errors.New("could not validate inclusion")
	}
	return inclusion, nil
}

func serializeProof(buf *bytes.Buffer, proof merkletree.MerkleProof) error {
	encodedSubtree, err := proof.Serialize()
	if err != nil {
		log.Println("could not serialize the subtree proof")
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(len(encodedSubtree)))
	if err != nil {
		log.Println("could not encoded length of proof")
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, encodedSubtree)
	if err != nil {
		log.Println("could not encode proof")
		return err
	}
	return nil
}

func deserializeProof(encoded []byte) (merkletree.MerkleProof, int, error) {
	size := int(binary.LittleEndian.Uint64(encoded[:BytesInInt]))
	if size <= 0 {
		log.Printf("IndexSize has to be positive: %d\n", size)
		return nil, -1, errors.New("size cannot be negative")
	}
	decoded, err := merkletree.DeserializeProof(encoded[BytesInInt : BytesInInt+size])
	if err != nil {
		log.Println("could not decode proof")
		return nil, -1, err
	}
	return decoded, size, nil
}

func VerifyInclusion(commDs *fr32.Fr32, sizeDS int, commDA *fr32.Fr32, sizeDA int, proofSubtree merkletree.MerkleProof) bool {
	element := merkletree.Node{Data: commDs.Data}
	root := merkletree.Node{Data: commDA.Data}
	if !proofSubtree.ValidateSubtree(&element, &root) {
		return false
	}
	// TOOD I am unsure what else needs to be validated here, in particular in relation to sizes
	return true
}

func VerifyCommEntryInclusion(commEntry *fr32.Fr32, commDA *fr32.Fr32, sizeDA int, proofDs merkletree.MerkleProof, idxDs int) bool {
	if !VerifyInclusion(commEntry, 2, commDA, sizeDA, proofDs) {
		return false
	}
	lvl, idx := containerPos(idxDs, sizeDA)
	if lvl != proofDs.Level() || idx != proofDs.Index() {
		return false
	}
	return true
}

func VerifyEntryInclusion(entry *Entry, commDA *fr32.Fr32, sizeDA int, subtreeProof merkletree.MerkleProof) bool {
	buf := new(bytes.Buffer)
	err := serializeFr32Entry(buf, entry)
	if err != nil {
		log.Println("could not serialize entry")
		return false
	}
	toHash := buf.Bytes()
	comm := fr32.Fr32{Data: merkletree.TruncatedHash(toHash).Data}
	return VerifyCommEntryInclusion(&comm, commDA, sizeDA, subtreeProof, entry.Offset)
}

// containerPos computes the position of the container proof elements by returning the level first and then the index
func containerPos(idxDs int, sizeDA int) (int, int) {
	// TODO figure out how to compute this
	return 1, 1
}
