package datasegment

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	cid "github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/xerrors"
)

type validationError string

var ErrValidation = validationError("unknown")

func (ve validationError) Error() string {
	return string(ve)
}

func (ve validationError) Is(err error) bool {
	_, ok := err.(validationError)
	return ok
}

const ChecksumSize = 16

const EntrySize = merkletree.NodeSize + 2*BytesInInt + ChecksumSize

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

func MakeIndexFromCommLoc(dealInfos []merkletree.CommAndLoc) (*IndexData, error) {
	entries := make([]SegmentDesc, 0, len(dealInfos))
	for _, di := range dealInfos {
		sd := SegmentDesc{
			CommDs: di.Comm,
			Offset: di.Loc.LeafIndex() * merkletree.NodeSize,
			Size:   1 << di.Loc.Level * merkletree.NodeSize,
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

var _ encoding.BinaryMarshaler = IndexData{}
var _ encoding.BinaryUnmarshaler = (*IndexData)(nil)

func (id IndexData) MarshalBinary() (data []byte, err error) {
	res := make([]byte, EntrySize*len(id.Entries))
	for i, r := range id.Entries {
		r.SerializeFr32Into(res[i*EntrySize : (i+1)*EntrySize])
	}
	return res, nil
}

func (id *IndexData) UnmarshalBinary(data []byte) error {
	if rem := len(data) % EntrySize; rem != 0 {
		return xerrors.Errorf("data to unmarshal is not a multiple of EntrySize: %d % %d != 0 (%d)",
			len(data), EntrySize, rem)
	}

	*id = IndexData{}
	id.Entries = make([]SegmentDesc, len(data)/EntrySize)
	for i := 0; i < len(id.Entries); i++ {
		err := id.Entries[i].UnmarshalBinary(data[i*EntrySize : (i+1)*EntrySize])
		if err != nil {
			return xerrors.Errorf("unamrshaling entry at index %d: %w", i, err)
		}
	}
	return nil
}

func (id IndexData) Validate() error {
	for i, e := range id.Entries {
		if err := e.Validate(); err != nil {
			return xerrors.Errorf("entry at index %d failed validation: %w", i, err)
		}
	}
	return nil
}

// ValidEntries returns a slice of entries in the index which pass validation checks
func (id IndexData) ValidEntries() ([]SegmentDesc, error) {
	res := []SegmentDesc{}
	for i, e := range id.Entries {

		if err := e.Validate(); err != nil {
			if errors.Is(err, ErrValidation) {
				continue
			} else {
				return nil, xerrors.Errorf("got unknown error for entry %d: %w", i, err)
			}
		}
		res = append(res, e)
	}
	return res, nil
}

// SegmentDesc contains a data segment description to be contained as two Fr32 elements in 2 leaf nodes of the data segment index
type SegmentDesc struct {
	// Commitment to the data segment (Merkle node which is the root of the subtree containing all the nodes making up the data segment)
	CommDs merkletree.Node
	// Ofset is the offset from the start of the deal in padded bytes
	Offset uint64
	// Size is the number of padded bytes that is contained in the sub-deal reflected by this SegmentDesc
	Size uint64
	// Checksum is a 126 bit checksum (SHA256) computes on CommDs || Offset || Size
	Checksum [ChecksumSize]byte
}

// PieceCID returns the PieceCID of the sub-deal
func (sd SegmentDesc) PieceCID() cid.Cid {
	c, err := commcid.PieceCommitmentV1ToCID(sd.CommDs[:])
	if err != nil {
		panic("CommDs is always 32 bytes: " + err.Error())
	}
	return c
}

// UnpaddedOffest returns unpadded offset relative of the sub-deal relative to the deal start
func (sd SegmentDesc) UnpaddedOffest() uint64 {
	return sd.Offset - sd.Offset/128
}

// UnpaddedLength returns unpadded length of the sub-deal
func (sd SegmentDesc) UnpaddedLength() uint64 {
	return sd.Size - sd.Size/128
}

func (sd SegmentDesc) CommAndLoc() merkletree.CommAndLoc {
	lvl := util.Log2Ceil(sd.Size / merkletree.NodeSize)
	res := merkletree.CommAndLoc{
		Comm: sd.CommDs,
		Loc: merkletree.Location{
			Level: lvl,
			Index: sd.Offset / merkletree.NodeSize >> lvl,
		},
	}
	fmt.Printf("commLoc: %+v\n", res)
	return res
}

func (sd SegmentDesc) computeChecksum() [ChecksumSize]byte {
	sdCopy := sd
	sdCopy.Checksum = [ChecksumSize]byte{}

	toHash := sdCopy.SerializeFr32()
	digest := sha256.Sum256(toHash)
	res := digest[:ChecksumSize]
	// Truncate to  126 bits
	res[ChecksumSize-1] &= 0b00111111
	return *(*[ChecksumSize]byte)(res)
}

func (sd SegmentDesc) withUpdatedChecksum() SegmentDesc {
	sd.Checksum = sd.computeChecksum()
	return sd
}

var _ encoding.BinaryMarshaler = SegmentDesc{}
var _ encoding.BinaryUnmarshaler = (*SegmentDesc)(nil)

func (sd SegmentDesc) MarshalBinary() ([]byte, error) {
	return sd.SerializeFr32(), nil
}

func (sd *SegmentDesc) UnmarshalBinary(data []byte) error {
	if len(data) != EntrySize {
		return xerrors.Errorf("invalid segment description size")
	}
	le := binary.LittleEndian

	*sd = SegmentDesc{}
	sd.CommDs = *(*merkletree.Node)(data)
	sd.Offset = le.Uint64(data[merkletree.NodeSize:])
	sd.Size = le.Uint64(data[merkletree.NodeSize+8:])
	sd.Checksum = *(*[ChecksumSize]byte)(data[merkletree.NodeSize+8+8:])

	if len(data[merkletree.NodeSize+8+8+ChecksumSize:]) != 0 {
		panic("sanity check, should have consumed all")
	}

	return nil
}

func (sd SegmentDesc) SerializeFr32() []byte {
	res := make([]byte, EntrySize)
	sd.SerializeFr32Into(res)
	return res
}

// SerializeFr32Into serializes the Segment Desctipion into given slice
// Panics if len(slice) < EntrySize
func (sd SegmentDesc) SerializeFr32Into(slice []byte) {
	_ = slice[EntrySize-1]

	le := binary.LittleEndian
	copy(slice, sd.CommDs[:])
	le.PutUint64(slice[merkletree.NodeSize:], sd.Offset)
	le.PutUint64(slice[merkletree.NodeSize+8:], sd.Size)
	copy(slice[merkletree.NodeSize+16:], sd.Checksum[:])
}

func (sd SegmentDesc) IntoNodes() [2]merkletree.Node {
	res := sd.SerializeFr32()
	return [2]merkletree.Node{
		*(*merkletree.Node)(res[:merkletree.NodeSize]),
		*(*merkletree.Node)(res[merkletree.NodeSize:]),
	}
}

func (sd SegmentDesc) Validate() error {
	if sd.computeChecksum() != sd.Checksum {
		return validationError("computed checksum does not match embedded checksum")
	}
	if sd.Offset%128 != 0 {
		return validationError("offset is not aligned in unpadded data")
	}
	if sd.Size%128 != 0 {
		return validationError("size is not aligned in unpadded data")
	}
	return nil
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
func MakeDataSegmentIdxWithChecksum(commDs *fr32.Fr32, offset uint64, size uint64, checksum *[ChecksumSize]byte) (SegmentDesc, error) {
	en := SegmentDesc{
		CommDs:   *(*merkletree.Node)(commDs),
		Offset:   offset,
		Size:     size,
		Checksum: *checksum,
	}
	if err := en.Validate(); err != nil {
		return SegmentDesc{}, xerrors.Errorf("input does not form a valid SegmentDesc: %w", err)
	}
	return en, nil
}

func MakeDataSegmentIndexEntry(CommP *fr32.Fr32, offset uint64, size uint64) (*SegmentDesc, error) {
	en := SegmentDesc{
		CommDs:   *(*merkletree.Node)(CommP),
		Offset:   offset,
		Size:     size,
		Checksum: [ChecksumSize]byte{},
	}
	en.Checksum = en.computeChecksum()
	return &en, nil
}

func MakeDataSegmentIdx(commDs *fr32.Fr32, offset uint64, size uint64) (SegmentDesc, error) {
	checksum, err := computeChecksum((*merkletree.Node)(commDs), offset, size)
	if err != nil {
		log.Println("could not compute checksum")
		return SegmentDesc{}, err
	}
	return MakeDataSegmentIdxWithChecksum(commDs, offset, size, checksum)
}

func MakeSegDescs(segments []merkletree.Node, segmentSizes []uint64) ([]merkletree.Node, error) {
	if len(segments) != len(segmentSizes) {
		return nil, xerrors.New("number of segment roots and segment sizes has to match")
	}
	res := make([]merkletree.Node, 2*len(segments))
	curOffset := uint64(0)
	for i, segment := range segments {
		s := fr32.Fr32(segment)
		// TODO: fix segment desciption to be in bytes
		// XXX
		currentDesc, err := MakeDataSegmentIdx(&s, curOffset*merkletree.NodeSize, segmentSizes[i]*merkletree.NodeSize)
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

func computeChecksum(commDs *merkletree.Node, offset uint64, size uint64) (*[ChecksumSize]byte, error) {

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
	res := digest[:ChecksumSize]
	// Reduce the size to 126 bits
	res[ChecksumSize-1] &= 0b00111111
	if *(*[ChecksumSize]byte)(res) != checkSum {
		panic("wrong checksum")
	}
	return (*[ChecksumSize]byte)(res), nil
}

func validateChecksum(en *SegmentDesc) (bool, error) {
	refChecksum, err := computeChecksum(&(en.CommDs), en.Offset, en.Size)
	if err != nil {
		return false, xerrors.Errorf("computing checksum: %w", err)
	}
	return bytes.Equal(refChecksum[:], en.Checksum[:]), nil
}

var lengthBufIndexData = []byte{129}

// adjusted encoder, allowing 2Mi entries in the Index
func (t *IndexData) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if _, err := cw.Write(lengthBufIndexData); err != nil {
		return err
	}

	// t.Entries ([]datasegment.SegmentDesc) (slice)
	if len(t.Entries) > 2<<20 {
		return xerrors.Errorf("Slice value in field t.Entries was too long")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajArray, uint64(len(t.Entries))); err != nil {
		return err
	}
	for _, v := range t.Entries {
		if err := v.MarshalCBOR(cw); err != nil {
			return err
		}
	}
	return nil
}

// adjusted decoder, allowing 2Mi entries in the Index
func (t *IndexData) UnmarshalCBOR(r io.Reader) (err error) {
	*t = IndexData{}

	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 1 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// t.Entries ([]datasegment.SegmentDesc) (slice)

	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > 2<<20 {
		return fmt.Errorf("t.Entries: array too large (%d)", extra)
	}

	if maj != cbg.MajArray {
		return fmt.Errorf("expected cbor array")
	}

	if extra > 0 {
		t.Entries = make([]SegmentDesc, extra)
	}

	for i := 0; i < int(extra); i++ {

		var v SegmentDesc
		if err := v.UnmarshalCBOR(cr); err != nil {
			return err
		}

		t.Entries[i] = v
	}

	return nil
}
