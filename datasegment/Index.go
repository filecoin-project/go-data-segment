package datasegment

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	"golang.org/x/xerrors"
)

const BytesInChecksum int = 16

const minIndexSize int = BytesInInt + EntrySize
const EntrySize int = fr32.BytesNeeded + 2*BytesInInt + BytesInChecksum

// MaxIndexEntriesInDeal defines the maximum number of index entries in for a given size of a deal
func MaxIndexEntriesInDeal(dealSize uint64) uint {
	res := uint(1) << util.Log2Ceil(dealSize/2048/uint64(EntrySize))
	if res < 4 {
		return 4
	}
	return res
}

type Index interface {
	// NumberEntries is the number of entries
	NumberEntries() int
	// IndexSize is the size of the index. Defined to be number of entries * 64 bytes
	IndexSize() int

	Start() int
	// SegmentDesc returns the SegmentDescIdx in position of index. 0-indexed
	SegmentDesc(index int) *SegmentDescIdx
}

type IndexData struct {
	entries []*SegmentDescIdx
}

func MakeIndex(entries []*SegmentDescIdx) (*IndexData, error) {
	index := IndexData{
		entries: entries,
	}
	if err := validateIndexStructure(&index); err != nil {
		return nil, xerrors.Errorf("input data is invalid: %w", err)
	}
	return &index, nil
}

// NumberEntries returns the number of entries
func (i IndexData) NumberEntries() int {
	return len(i.entries)
}

// IndexSize returns the size of the index. Defined to be number of entries * 64 bytes
func (i IndexData) IndexSize() uint64 {
	return uint64(i.NumberEntries()) * uint64(EntrySize)
}

// SegmentDesc returns the SegmentDescIdx in position of index. 0-indexed
func (i IndexData) SegmentDesc(index int) *SegmentDescIdx {
	return i.entries[index]
}

// SegmentDescIdx contains a data segment description to be contained as two Fr32 elements in 2 leaf nodes of the data segment index
type SegmentDescIdx struct {
	// Commitment to the data segment (Merkle node which is the root of the subtree containing all the nodes making up the data segment)
	CommDs fr32.Fr32
	// Offset the first leaf which contains this data segment, thus multiplying with 32 indicates how many bytes into the deal this client's data segment starts. 0-indexed.
	Offset uint64
	// Size is the amount of 32-byte nodes (leafs) that is contained in the deal reflected by the SegmentDescIdx
	Size uint64
	// Checksum is a 126 bit checksum (SHA256) computes on CommDs || Offset || Size
	Checksum [BytesInChecksum]byte
}

func (sdi SegmentDescIdx) computeChecksum() [BytesInChecksum]byte {
	sdiCopy := sdi
	sdiCopy.Checksum = [BytesInChecksum]byte{}

	toHash := sdiCopy.SerializeFr32()
	digest := sha256.Sum256(toHash)
	res := digest[:BytesInChecksum]
	// Reduce the size to 126 bits
	res[BytesInChecksum-1] &= 0b00111111
	return *(*[BytesInChecksum]byte)(res)
}

func (sdi SegmentDescIdx) SerializeFr32() []byte {
	res := make([]byte, 0, EntrySize)
	le := binary.LittleEndian

	res = append(res, sdi.CommDs[:]...)
	res = le.AppendUint64(res, sdi.Offset)
	res = le.AppendUint64(res, sdi.Size)
	res = append(res, sdi.Checksum[:]...)

	return res
}

func (ds SegmentDescIdx) MakeNode() (merkletree.Node, merkletree.Node, error) {
	buf := new(bytes.Buffer)
	err := serializeFr32Entry(buf, &ds)
	data := buf.Bytes()
	if err != nil {
		log.Println("could not serialize node")
		return merkletree.Node{}, merkletree.Node{}, err
	}
	node1 := *(*merkletree.Node)(data[:fr32.BytesNeeded])
	node2 := *(*merkletree.Node)(data[fr32.BytesNeeded:])
	return node1, node2, nil
}
func MakeDataSegmentIdxWithChecksum(commDs *fr32.Fr32, offset uint64, size uint64, checksum *[BytesInChecksum]byte) (*SegmentDescIdx, error) {
	en := SegmentDescIdx{
		CommDs:   *commDs,
		Offset:   offset,
		Size:     size,
		Checksum: *checksum,
	}
	if err := validateEntry(&en); err != nil {
		return nil, xerrors.Errorf("input does not form a valid SegmentDescIdx: %w", err)
	}
	return &en, nil
}

func MakeDataSegmentIndexEntry(CommP *fr32.Fr32, offset uint64, size uint64) (*SegmentDescIdx, error) {
	en := SegmentDescIdx{
		CommDs:   *CommP,
		Offset:   offset,
		Size:     size,
		Checksum: [BytesInChecksum]byte{},
	}
	en.Checksum = en.computeChecksum()
	return &en, nil
}

func MakeDataSegmentIdx(commDs *fr32.Fr32, offset uint64, size uint64) (*SegmentDescIdx, error) {
	checksum, err := computeChecksum(commDs, offset, size)
	if err != nil {
		log.Println("could not compute checksum")
		return nil, err
	}
	return MakeDataSegmentIdxWithChecksum(commDs, offset, size, checksum)
}

func MakeSegDescs(segments []merkletree.Node, segmentSizes []uint64) ([]merkletree.Node, error) {
	if len(segments) != len(segmentSizes) {
		return nil, errors.New("number of segment roots and segment sizes has to match")
	}
	res := make([]merkletree.Node, 2*len(segments))
	curOffset := uint64(0)
	for i, segment := range segments {
		s := fr32.Fr32(segment)
		currentDesc, err := MakeDataSegmentIdx(&s, curOffset, segmentSizes[i])
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
func SegmentRoot(treeDepth int, segmentSize uint64, segmentOffset uint64) (int, uint64) {
	lvl := treeDepth - util.Log2Ceil(uint64(segmentSize)) - 1
	idx := segmentOffset >> util.Log2Ceil(uint64(segmentSize))
	return lvl, idx
}

// serializeFr32Entry uses a buffer to serialize en SegmentDescIdx into a byte slice
func serializeFr32Entry(buf *bytes.Buffer, entry *SegmentDescIdx) error {
	err := binary.Write(buf, binary.LittleEndian, entry.CommDs)
	if err != nil {
		return xerrors.Errorf("writing CommD: %w", err)
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(entry.Offset))
	if err != nil {
		return xerrors.Errorf("writing Offset: %w", err)
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(entry.Size))
	if err != nil {
		return xerrors.Errorf("writing Size: %w", err)
	}
	err = binary.Write(buf, binary.LittleEndian, entry.Checksum)
	if err != nil {
		return xerrors.Errorf("writing Checksum: %w", err)
	}
	return nil
}

// SerializeIndex encodes a data segment Inclusion into a byte array, after validating that the structure is valid
func SerializeIndex(index *IndexData) ([]byte, error) {
	if err := validateIndexStructure(index); err != nil {
		return nil, xerrors.Errorf("the index is not valid: %w", err)
	}
	res, err := serializeIndex(index)
	if err != nil {
		log.Println("could not serialize index")
		return nil, err
	}
	return res, nil
}

// serializeIndex encodes a data segment Inclusion into a byte array without doing validation
func serializeIndex(index *IndexData) ([]byte, error) {
	buf := new(bytes.Buffer)
	for i := 0; i < index.NumberEntries(); i++ {
		err := serializeFr32Entry(buf, index.SegmentDesc(i))
		if err != nil {
			log.Printf("could not write SegmentDescIdx %d\n", i)
			return nil, xerrors.Errorf("could not write data segment (index %d): %w", i, err)
		}
	}
	return buf.Bytes(), nil
}

// deserializeFr32Entry deserializes a byte slice into an SegmentDescIdx
func deserializeFr32Entry(encoded []byte) (*SegmentDescIdx, error) {
	if len(encoded) < EntrySize {
		return nil, xerrors.Errorf("passed encoded entry too small: %d < %d", len(encoded), EntrySize)
	}
	ctr := 0
	commDs := (*[fr32.BytesNeeded]byte)(encoded[ctr : ctr+fr32.BytesNeeded])
	ctr += fr32.BytesNeeded
	offset := binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt])
	ctr += BytesInInt
	size := binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt])
	ctr += BytesInInt
	checksum := *(*[BytesInChecksum]byte)(encoded[ctr : ctr+BytesInChecksum])
	ctr += BytesInChecksum
	en := SegmentDescIdx{
		CommDs:   *(*fr32.Fr32)(commDs),
		Offset:   offset,
		Size:     size,
		Checksum: checksum,
	}
	return &en, nil
}

// DeserializeIndex decodes a byte array into a data segment Index and validates the structure
// Assumes the index is FR32 padded
func DeserializeIndex(encoded []byte) (*IndexData, error) {
	// Check that at least one SegmentDescIdx is included
	if len(encoded) > 0 && len(encoded)%EntrySize != 0 {
		return nil, errors.New("no legal data segment index encoding")
	}
	index, err := deserializeIndex(encoded)
	if err != nil {
		return nil, xerrors.Errorf("deserialising index: %w", err)
	}

	if err := validateIndexStructure(index); err != nil {
		return nil, xerrors.Errorf("deserialized structure is not valid: %w", err)
	}
	return index, nil
}

// deserializeIndex decodes a byte array into a data segment Index, without any validation
// Assumes the index is FR32 padded
func deserializeIndex(encoded []byte) (*IndexData, error) {
	entries := len(encoded) / EntrySize
	decoded := make([]*SegmentDescIdx, entries)
	ctr := 0
	var err error
	for i := 0; i < entries; i++ {
		decoded[i], err = deserializeFr32Entry(encoded[ctr : ctr+EntrySize])
		if err != nil {
			return nil, xerrors.Errorf("decoding entry at position %d: %w", i, err)
		}

		ctr += EntrySize
	}
	return &IndexData{entries: decoded}, nil
}

func validateIndexStructure(index *IndexData) error {
	if index == nil {
		return xerrors.Errorf("index is nil")
	}
	if index.NumberEntries() <= 0 {
		return xerrors.Errorf("number of deal entries must be positive, %d < 0", index.NumberEntries())
	}
	for i, e := range index.entries {
		if err := validateEntry(e); err != nil {
			return xerrors.Errorf("invalid entry at index %d: %w", i, err)
		}
	}
	return nil
}

func validateEntry(en *SegmentDescIdx) error {
	ok, err := validateChecksum(en)
	if err != nil {
		return xerrors.Errorf("validating checksum: %w", err)
	}
	if !ok {
		return xerrors.Errorf("checksum invalid")
	}
	return nil

}

func computeChecksum(commDs *fr32.Fr32, offset uint64, size uint64) (*[BytesInChecksum]byte, error) {
	buf := new(bytes.Buffer)
	tempEntry := SegmentDescIdx{
		CommDs:   *commDs,
		Offset:   offset,
		Size:     size,
		Checksum: [16]byte{},
	}
	err := serializeFr32Entry(buf, &tempEntry)
	if err != nil {
		return nil, xerrors.Errorf("serailising entry: %w", err)
	}
	// We want to hash the SegmentDescIdx, excluding the computeChecksum as it is what we are trying to compute
	toHash := buf.Bytes()[:EntrySize]
	digest := sha256.Sum256(toHash)
	res := digest[:BytesInChecksum]
	// Reduce the size to 126 bits
	res[BytesInChecksum-1] &= 0b00111111
	return (*[BytesInChecksum]byte)(res), nil
}

func validateChecksum(en *SegmentDescIdx) (bool, error) {
	refChecksum, err := computeChecksum(&(en.CommDs), en.Offset, en.Size)
	if err != nil {
		return false, xerrors.Errorf("computing checksum: %w", err)
	}
	return bytes.Equal(refChecksum[:], en.Checksum[:]), nil
}
