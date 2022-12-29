package datasegment

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"log"
)

// BytesInInt represents the amount of bytes used to encode an int
const BytesInInt int = 64 / 8

type Structure struct {
	commDA fr32.Fr32
	// size of the aggregator's data in bytes
	size int
	// pos indicates the 0-indexed (compact) position of the client's data within the aggregator's data
	pos int
	// idxDs indicates the 0-indexed position of data segment
	idxDs int
	// proofSubtree proof of inclusion of the client's data in the data aggregator's Merkle tree (includes position information)
	proofSubtree merkletree.MerkleProof
	// proofDs leaf inclusion proof (includes position information)
	proofDs merkletree.MerkleProof
}

type InternalType interface {
	position | int64
}

type position struct {
	lvl int
	idx int
}

// Serialize encodes a data segment Structure into a byte array
func Serialize(structure Structure) ([]byte, error) {
	if !validateStructure(structure) {
		return nil, errors.New("the structure is not valid")
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, structure.commDA)
	if err != nil {
		log.Println("could not write the commitment")
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(structure.size))
	if err != nil {
		log.Println("could not write size")
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(structure.pos))
	if err != nil {
		log.Println("could not write position")
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(structure.idxDs))
	if err != nil {
		log.Println("could not write index")
		return nil, err
	}
	err = serializeProof(buf, structure.proofSubtree)
	if err != nil {
		return nil, err
	}
	err = serializeProof(buf, structure.proofDs)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func validateStructure(structure Structure) bool {
	if structure.size <= 0 {
		log.Println("size of aggregator's data must be positive")
		return false
	}
	if structure.idxDs < 0 {
		log.Println("index in data segment cannot be negative")
		return false
	}
	if structure.pos < 0 {
		log.Println("position in data segment cannot be negative")
		return false
	}
	return true
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

// Deserialize decodes a byte array into a data segment Structure
func Deserialize(encoded []byte) (Structure, error) {
	// 5 integers includes the size, pos, idxDa and the size of the two Merkle proofs
	if encoded == nil || len(encoded) < fr32.BytesNeeded+5*BytesInInt {
		log.Println("no data segment structure encoded")
		return Structure{}, errors.New("no data segment structure encoded")
	}
	ctr := 0
	commDA := (*[fr32.BytesNeeded]byte)(encoded[ctr:fr32.BytesNeeded])
	ctr += fr32.BytesNeeded
	size := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	pos := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	idxDs := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	subtreeProof, subtreeProofSize, err := deserializeProof(encoded[ctr:])
	if err != nil || subtreeProofSize <= 0 {
		return Structure{}, errors.New("no data segment structure encoded")
	}
	ctr += subtreeProofSize + BytesInInt
	proofDs, dsProofSize, err := deserializeProof(encoded[ctr:])
	if err != nil || dsProofSize <= 0 {
		return Structure{}, errors.New("no data segment structure encoded")
	}
	structure := Structure{
		commDA:       fr32.Fr32{Data: *commDA},
		size:         size,
		pos:          pos,
		idxDs:        idxDs,
		proofSubtree: subtreeProof,
		proofDs:      proofDs,
	}
	if !validateStructure(structure) {
		return Structure{}, errors.New("could not validate structure")
	}
	return structure, nil
}

func deserializeProof(encoded []byte) (merkletree.MerkleProof, int, error) {
	size := int(binary.LittleEndian.Uint64(encoded[:BytesInInt]))
	if size <= 0 {
		log.Println(fmt.Sprintf("size has to be positive: %d", size))
		return nil, -1, errors.New("size cannot be negative")
	}
	decoded, err := merkletree.DeserializeProof(encoded[BytesInInt : BytesInInt+size])
	if err != nil {
		log.Println("could not decode proof")
		return nil, -1, err
	}
	return decoded, size, nil
}
