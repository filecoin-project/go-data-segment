package datasegment

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	"log"
)

const BitsInChecksum int = 126
const BytesInChecksum int = 16

const minIndexSize int = BytesInInt + entrySize

type Index interface {
	// NumberEntries is the number of entries
	NumberEntries() int
	// IndexSize is the size of the index. Defined to be number of entries * 64 bytes
	IndexSize() int
	// DealSize is the size of the deal
	DealSize() int
	// Start is the start of the index, defined to be (DealSize - IndexSize) & 0xc0ffffff_ffffffff (in little endian, so the two most significant bits must be 0)
	Start() int
	// SegmentDesc returns the SegmentDescIdx in position of index. 0-indexed
	SegmentDesc(index int) *SegmentDescIdx
}

type indexData struct {
	dealSize int
	entries  []*SegmentDescIdx
}

func MakeIndex(entries []*SegmentDescIdx, dealSize int) (Index, error) {
	index := indexData{
		dealSize: dealSize,
		entries:  entries,
	}
	if !validateIndexStructure(index) {
		return nil, errors.New("input data is invalid")
	}
	return index, nil
}

// NumberEntries returns the number of entries
func (i indexData) NumberEntries() int {
	return len(i.entries)
}

// IndexSize returns the size of the index. Defined to be number of entries * 64 bytes
func (i indexData) IndexSize() int {
	return i.NumberEntries() * 64
}

// DealSize returns the size of deal
func (i indexData) DealSize() int {
	return i.dealSize
}

// Start returns the start of the index, defined to be (size of deal - Size) & 0xc0ffffff_ffffffff (in little endian, so the two most significant bits must be 0)
func (i indexData) Start() int {
	return int((uint64(i.DealSize()) - uint64(i.IndexSize())) & 0xc0ffffff_ffffffff)
}

// SegmentDesc returns the SegmentDescIdx in position of index. 0-indexed
func (i indexData) SegmentDesc(index int) *SegmentDescIdx {
	return i.entries[index]
}

const entrySize int = fr32.BytesNeeded + 2*BytesInInt + BytesInChecksum

// SegmentDescIdx contains a data segment description to be contained as two Fr32 elements in 2 leaf nodes of the data segment index
type SegmentDescIdx struct {
	// Commitment to the data segment (Merkle node which is the root of the subtree containing all the nodes making up the data segment)
	CommDs fr32.Fr32
	// Offset the first leaf which contains this data segment, thus multiplying with 32 indicates how many bytes into the deal this client's data segment starts. 0-indexed.
	Offset int
	// Size is the amount of 32-byte nodes (leafs) that is contained in the deal reflected by the SegmentDescIdx
	Size int
	// Checksum is a 126 bit checksum (SHA256) computes on CommDs || Offset || Size
	Checksum [BytesInChecksum]byte
}

func (ds SegmentDescIdx) MakeNode() (merkletree.Node, merkletree.Node, error) {
	buf := new(bytes.Buffer)
	err := serializeFr32Entry(buf, &ds)
	data := buf.Bytes()
	if err != nil {
		log.Println("could not serialize node")
		return merkletree.Node{}, merkletree.Node{}, err
	}
	node1 := merkletree.Node{Data: *(*[fr32.BytesNeeded]byte)(data[:fr32.BytesNeeded])}
	node2 := merkletree.Node{Data: *(*[fr32.BytesNeeded]byte)(data[fr32.BytesNeeded:])}
	return node1, node2, nil
}
func MakeDataSegmentIdxWithChecksum(commDs *fr32.Fr32, offset int, size int, checksum *[BytesInChecksum]byte) (*SegmentDescIdx, error) {
	en := SegmentDescIdx{
		CommDs:   *commDs,
		Offset:   offset,
		Size:     size,
		Checksum: *checksum,
	}
	if !validateEntry(&en) {
		return nil, errors.New("input does not form a valid SegmentDescIdx")
	}
	return &en, nil
}

func MakeDataSegmentIdx(commDs *fr32.Fr32, offset int, size int) (*SegmentDescIdx, error) {
	checksum, err := computeChecksum(commDs, offset, size)
	if err != nil {
		log.Println("could not compute checksum")
		return nil, err
	}
	return MakeDataSegmentIdxWithChecksum(commDs, offset, size, checksum)
}

func MakeSegDescs(segments []merkletree.Node, segmentSizes []int) ([]merkletree.Node, error) {
	if len(segments) != len(segmentSizes) {
		return nil, errors.New("incorrect amount of segments and sizes")
	}
	res := make([]merkletree.Node, 2*len(segments))
	curOffset := 0
	for i, segment := range segments {
		currentDesc, err := MakeDataSegmentIdx(&fr32.Fr32{Data: segment.Data}, curOffset, segmentSizes[i])
		if err != nil {
			return nil, err
		}
		node1, node2, errNode := currentDesc.MakeNode()
		if errNode != nil {
			return nil, errNode
		}
		res[2*i] = node1
		res[2*i+1] = node2
		// TODO currently only rounding to nearest subtree. Thus to be fully robust it must be updated
		curOffset += segmentSizes[i]
	}
	return res, nil
}

// SegmentRoot computes the root of the client's segment's subtree
// treeDepth is the depth of the tree where the client segment is located
// segmentSize is the amount of leafs needed for the client's segment
// segmentOffset is the index of the first leaf where the client's segment starts. 0-indexed
func SegmentRoot(treeDepth int, segmentSize int, segmentOffset int) (int, int) {
	lvl := treeDepth - util.Log2Ceil(segmentSize) - 1
	idx := segmentOffset >> util.Log2Ceil(segmentSize)
	return lvl, idx
}

// serializeFr32Entry uses a buffer to serialize en SegmentDescIdx into a byte slice
func serializeFr32Entry(buf *bytes.Buffer, entry *SegmentDescIdx) error {
	err := binary.Write(buf, binary.LittleEndian, entry.CommDs.Data)
	if err != nil {
		log.Println("could not write the commitment of SegmentDescIdx")
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(entry.Offset))
	if err != nil {
		log.Printf("could not write Offset %d of SegmentDescIdx\n", entry.Offset)
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(entry.Size))
	if err != nil {
		log.Printf("could not write IndexSize %d of SegmentDescIdx\n", entry.Size)
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, entry.Checksum)
	if err != nil {
		log.Println("could not write checksum of SegmentDescIdx")
		return err
	}
	return nil
}

// SerializeIndex encodes a data segment Inclusion into a byte array, after validating that the structure is valid
func SerializeIndex(index Index) ([]byte, error) {
	if !validateIndexStructure(index) {
		return nil, errors.New("the index is not valid")
	}
	res, err := serializeIndex(index)
	if err != nil {
		log.Println("could not serialize index")
		return nil, err
	}
	return res, nil
}

// serializeIndex encodes a data segment Inclusion into a byte array without doing validation
func serializeIndex(index Index) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint64(index.DealSize()))
	if err != nil {
		log.Printf("could not write deal size %d\n", index.DealSize())
		return nil, err
	}
	for i := 0; i < index.NumberEntries(); i++ {
		err = serializeFr32Entry(buf, index.SegmentDesc(i))
		if err != nil {
			log.Printf("could not write SegmentDescIdx %d\n", i)
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// deserializeFr32Entry deserializes a byte slice into an SegmentDescIdx
func deserializeFr32Entry(encoded []byte) *SegmentDescIdx {
	ctr := 0
	commDs := (*[fr32.BytesNeeded]byte)(encoded[ctr : ctr+fr32.BytesNeeded])
	ctr += fr32.BytesNeeded
	offset := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	size := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	checksum := *(*[BytesInChecksum]byte)(encoded[ctr : ctr+BytesInChecksum])
	ctr += BytesInChecksum
	en := SegmentDescIdx{
		CommDs:   fr32.Fr32{Data: *commDs},
		Offset:   offset,
		Size:     size,
		Checksum: checksum,
	}
	return &en
}

// DeserializeIndex decodes a byte array into a data segment Index and validates the structure
// Assumes the index is FR32 padded
func DeserializeIndex(encoded []byte) (Index, error) {
	// Check that at least one SegmentDescIdx is included and that the size is appropriate
	if encoded == nil || len(encoded) < minIndexSize || (len(encoded)-minIndexSize)%entrySize != 0 {
		log.Println("no legal data segment index encoding")
		return nil, errors.New("no legal data segment index encoding")
	}
	index := deserializeIndex(encoded)
	if !validateIndexStructure(index) {
		log.Println("deserialized structure is not valid")
		return nil, errors.New("deserialized structure is not valid")
	}
	return index, nil
}

// deserializeIndex decodes a byte array into a data segment Index, without any validation
// Assumes the index is FR32 padded
func deserializeIndex(encoded []byte) Index {
	entries := len(encoded) / entrySize
	decoded := make([]*SegmentDescIdx, entries)
	ctr := 0
	dealSize := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	for i := 0; i < entries; i++ {
		decoded[i] = deserializeFr32Entry(encoded[ctr : ctr+entrySize])
		ctr += entrySize
	}
	return indexData{dealSize: dealSize, entries: decoded}
}

func validateIndexStructure(index Index) bool {
	if index == nil {
		log.Println("index is null")
		return false
	}
	if index.DealSize() <= 0 {
		log.Printf("amount of deals must be positive, it is %d\n", index.DealSize())
		return false
	}
	if index.NumberEntries() <= 0 {
		log.Printf("amount of deals entries be positive, it is %d\n", index.NumberEntries())
		return false
	}
	for i := 0; i < index.NumberEntries(); i++ {
		if !validateEntry(index.SegmentDesc(i)) {
			return false
		}
	}
	return true
}

func validateEntry(en *SegmentDescIdx) bool {
	if en.Size < 0 {
		log.Printf("size in SegmentDescIdx is %d, it must not be negative\n", en.Size)
		return false
	}
	if en.Offset < 0 {
		log.Printf("offset in SegmentDescIdx is %d, it must not be negative\n", en.Offset)
		return false
	}
	return validateChecksum(en)
}

func computeChecksum(commDs *fr32.Fr32, offset int, size int) (*[BytesInChecksum]byte, error) {
	buf := new(bytes.Buffer)
	tempEntry := SegmentDescIdx{
		CommDs:   *commDs,
		Offset:   offset,
		Size:     size,
		Checksum: [16]byte{},
	}
	err := serializeFr32Entry(buf, &tempEntry)
	if err != nil {
		log.Println("could not serialize commitment and integers")
		return nil, err
	}
	// We want to hash the SegmentDescIdx, excluding the computeChecksum as it is what we are trying to compute
	toHash := buf.Bytes()[:fr32.BytesNeeded+2*BytesInInt]
	digest := sha256.Sum256(toHash)
	res := digest[:BytesInChecksum]
	// Reduce the size to 126 bits
	res[BytesInChecksum-1] &= 0b00111111
	return (*[BytesInChecksum]byte)(res), nil
}

func validateChecksum(en *SegmentDescIdx) bool {
	refChecksum, err := computeChecksum(&(en.CommDs), en.Offset, en.Size)
	if err != nil {
		log.Println("could not serialize SegmentDescIdx")
		return false
	}
	if !bytes.Equal(refChecksum[:], en.Checksum[:]) {
		return false
	}
	return true
}
