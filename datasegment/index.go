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
	"github.com/filecoin-project/go-state-types/abi"
	"golang.org/x/xerrors"
)

const BytesInChecksum int = 16

const minIndexSize int = BytesInInt + EntrySize
const EntrySize int = fr32.BytesNeeded + 2*BytesInInt + BytesInChecksum

// MaxIndexEntriesInDeal defines the maximum number of index entries in for a given size of a deal
func MaxIndexEntriesInDeal(dealSize abi.PaddedPieceSize) uint {
	res := uint(1) << util.Log2Ceil(uint64(dealSize)/2048/uint64(EntrySize))
	if res < 4 {
		return 4
	}
	return res
}

type IndexData struct {
	Entries []SegmentDesc
}

func MakeIndex(entries []SegmentDesc) (*IndexData, error) {
	index := IndexData{
		Entries: entries,
	}
	if err := validateIndexStructure(&index); err != nil {
		return nil, xerrors.Errorf("input data is invalid: %w", err)
	}
	return &index, nil
}

func MakeIndexFromDealInfos(dealInfos []merkletree.DealInfo) (*IndexData, error) {
	entries := make([]SegmentDesc, 0, len(dealInfos))
	for _, di := range dealInfos {
		sd := SegmentDesc{
			CommDs: di.Comm,
			Offset: di.Index * di.Size,
			Size:   di.Size,
		}
		sd.Checksum = sd.computeChecksum()
		entries = append(entries, sd)
	}
	return &IndexData{Entries: entries}, nil
}

// NumberEntries returns the number of entries
func (i IndexData) NumberEntries() int {
	return len(i.Entries)
}

// IndexSize returns the size of the index. Defined to be number of entries * 64 bytes
func (i IndexData) IndexSize() uint64 {
	return uint64(i.NumberEntries()) * uint64(EntrySize)
}

// SegmentDesc returns the SegmentDesc in position of index. 0-indexed
func (i IndexData) SegmentDesc(index int) *SegmentDesc {
	return &i.Entries[index]
}

// SegmentDesc contains a data segment description to be contained as two Fr32 elements in 2 leaf nodes of the data segment index
type SegmentDesc struct {
	// Commitment to the data segment (Merkle node which is the root of the subtree containing all the nodes making up the data segment)
	CommDs merkletree.Node
	// Offset the first leaf which contains this data segment, thus multiplying with 32 indicates how many bytes into the deal this client's data segment starts. 0-indexed.
	Offset uint64
	// Size is the amount of 32-byte nodes (leafs) that is contained in the deal reflected by the SegmentDesc
	Size uint64
	// Checksum is a 126 bit checksum (SHA256) computes on CommDs || Offset || Size
	Checksum [BytesInChecksum]byte
}

func (sdi SegmentDesc) computeChecksum() [BytesInChecksum]byte {
	sdiCopy := sdi
	sdiCopy.Checksum = [BytesInChecksum]byte{}

	toHash := sdiCopy.SerializeFr32()
	digest := sha256.Sum256(toHash)
	res := digest[:BytesInChecksum]
	// Reduce the size to 126 bits
	res[BytesInChecksum-1] &= 0b00111111
	return *(*[BytesInChecksum]byte)(res)
}

func (sdi SegmentDesc) SerializeFr32() []byte {
	res := make([]byte, 0, EntrySize)
	res = sdi.SerializeFr32Into(res)

	return res
}

func (sdi SegmentDesc) SerializeFr32Into(slice []byte) []byte {
	le := binary.LittleEndian

	slice = append(slice, sdi.CommDs[:]...)
	slice = le.AppendUint64(slice, sdi.Offset)
	slice = le.AppendUint64(slice, sdi.Size)
	slice = append(slice, sdi.Checksum[:]...)
	return slice
}

func (sdi SegmentDesc) IntoNodes() [2]merkletree.Node {
	res := sdi.SerializeFr32()
	return [2]merkletree.Node{
		*(*merkletree.Node)(res[:merkletree.NodeSize]),
		*(*merkletree.Node)(res[merkletree.NodeSize:]),
	}
}

// ==============================

func (ds SegmentDesc) MakeNode() (merkletree.Node, merkletree.Node, error) {
	buf := new(bytes.Buffer)
	err := serializeFr32Entry(buf, &ds)
	data := buf.Bytes()
	if err != nil {
		return merkletree.Node{}, merkletree.Node{}, err
	}
	node1 := *(*merkletree.Node)(data[:fr32.BytesNeeded])
	node2 := *(*merkletree.Node)(data[fr32.BytesNeeded:])
	return node1, node2, nil
}
func MakeDataSegmentIdxWithChecksum(commDs *fr32.Fr32, offset uint64, size uint64, checksum *[BytesInChecksum]byte) (*SegmentDesc, error) {
	en := SegmentDesc{
		CommDs:   *(*merkletree.Node)(commDs),
		Offset:   offset,
		Size:     size,
		Checksum: *checksum,
	}
	if err := validateEntry(&en); err != nil {
		return nil, xerrors.Errorf("input does not form a valid SegmentDesc: %w", err)
	}
	return &en, nil
}

func MakeDataSegmentIndexEntry(CommP *fr32.Fr32, offset uint64, size uint64) (*SegmentDesc, error) {
	en := SegmentDesc{
		CommDs:   *(*merkletree.Node)(CommP),
		Offset:   offset,
		Size:     size,
		Checksum: [BytesInChecksum]byte{},
	}
	en.Checksum = en.computeChecksum()
	return &en, nil
}

func MakeDataSegmentIdx(commDs *fr32.Fr32, offset uint64, size uint64) (*SegmentDesc, error) {
	checksum, err := computeChecksum((*merkletree.Node)(commDs), offset, size)
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
		// TODO: fix segment desciption to be in bytes
		// XXX
		currentDesc, err := MakeDataSegmentIdx(&s, curOffset*BytesInNode, segmentSizes[i]*BytesInNode)
		if err != nil {
			return nil, err
		}
		node1, node2, errNode := currentDesc.MakeNode()
		if errNode != nil {
			return nil, errNode
		}
		res[2*i] = node1
		res[2*i+1] = node2
		curOffset += 1 << util.Log2Ceil(segmentSizes[i])
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

// serializeFr32Entry uses a buffer to serialize en SegmentDesc into a byte slice
func serializeFr32Entry(buf *bytes.Buffer, entry *SegmentDesc) error {
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
			log.Printf("could not write SegmentDesc %d\n", i)
			return nil, xerrors.Errorf("could not write data segment (index %d): %w", i, err)
		}
	}
	return buf.Bytes(), nil
}

// deserializeFr32Entry deserializes a byte slice into an SegmentDesc
func deserializeFr32Entry(encoded []byte) (*SegmentDesc, error) {
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
	en := SegmentDesc{
		CommDs:   *(*merkletree.Node)(commDs),
		Offset:   offset,
		Size:     size,
		Checksum: checksum,
	}
	return &en, nil
}

func validateIndexStructure(index *IndexData) error {
	if index == nil {
		return xerrors.Errorf("index is nil")
	}
	if index.NumberEntries() <= 0 {
		return xerrors.Errorf("number of deal entries must be positive, %d < 0", index.NumberEntries())
	}
	for i, e := range index.Entries {
		if err := validateEntry(&e); err != nil {
			return xerrors.Errorf("invalid entry at index %d: %w", i, err)
		}
	}
	return nil
}

func validateEntry(en *SegmentDesc) error {
	ok, err := validateChecksum(en)
	if err != nil {
		return xerrors.Errorf("validating checksum: %w", err)
	}
	if !ok {
		return xerrors.Errorf("checksum invalid")
	}
	return nil

}

func computeChecksum(commDs *merkletree.Node, offset uint64, size uint64) (*[BytesInChecksum]byte, error) {

	buf := new(bytes.Buffer)
	tempEntry := SegmentDesc{
		CommDs:   *(*merkletree.Node)(commDs),
		Offset:   offset,
		Size:     size,
		Checksum: [16]byte{},
	}
	checkSum := tempEntry.computeChecksum()
	err := serializeFr32Entry(buf, &tempEntry)
	if err != nil {
		return nil, xerrors.Errorf("serailising entry: %w", err)
	}
	// We want to hash the SegmentDesc, excluding the computeChecksum as it is what we are trying to compute
	toHash := buf.Bytes()[:EntrySize]
	digest := sha256.Sum256(toHash)
	res := digest[:BytesInChecksum]
	// Reduce the size to 126 bits
	res[BytesInChecksum-1] &= 0b00111111
	if *(*[BytesInChecksum]byte)(res) != checkSum {
		panic("wrong checksum")
	}
	return (*[BytesInChecksum]byte)(res), nil
}

func validateChecksum(en *SegmentDesc) (bool, error) {
	refChecksum, err := computeChecksum(&(en.CommDs), en.Offset, en.Size)
	if err != nil {
		return false, xerrors.Errorf("computing checksum: %w", err)
	}
	return bytes.Equal(refChecksum[:], en.Checksum[:]), nil
}
