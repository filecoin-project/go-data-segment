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

type PieceIndex interface {
	InitFromDeals(dealInfos []merkletree.CommAndLoc) error
	NumEntries() int
	Entry(idx int) *SegmentDesc
	Search(cid cid.Cid) int

	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

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

// EntrySize is the size of a Data Segment Index Entry v2
// v2 entries consist of 4 Merkle nodes (4 * 32 = 128 bytes)
// This is the serialized size in memory (padded format, aligned to 128-byte boundaries).
const EntrySize = 4 * merkletree.NodeSize // 128 bytes (4 nodes of 32 bytes each)

// Multicodec values
const (
	MulticodecRaw = 0x55   // Raw binary data
	MulticodecCAR = 0x0202 // CAR format (IPLD)
)

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

var _ PieceIndex = (*IndexData)(nil)

// InitFromDeals initializes the index from deal information
func (id *IndexData) InitFromDeals(dealInfos []merkletree.CommAndLoc) error {
	entries := make([]SegmentDesc, 0, len(dealInfos))
	for _, di := range dealInfos {
		size := 1 << di.Loc.Level * merkletree.NodeSize
		sd := SegmentDesc{
			CommDs:              di.Comm,
			Offset:              di.Loc.LeafIndex() * merkletree.NodeSize,
			Size:                uint64(size),
			RawSize:             uint64(size), // Default to size for v1 compatibility
			Multicodec:          MulticodecRaw,
			MulticodecDependent: merkletree.Node{},
			ACLType:             0,
			ACLData:             0,
			Reserved:            [7]byte{},
			Checksum:            [ChecksumSize]byte{},
		}
		sd.Checksum = sd.computeChecksum()
		entries = append(entries, sd)
	}
	id.Entries = entries
	return nil
}

// NumEntries returns the number of entries in the index
func (id IndexData) NumEntries() int {
	return len(id.Entries)
}

// Entry returns the segment description at the given index
func (id IndexData) Entry(idx int) *SegmentDesc {
	if idx < 0 || idx >= len(id.Entries) {
		return nil
	}
	return &id.Entries[idx]
}

// Search finds the index of a segment by its PieceCID
// Returns -1 if not found
func (id IndexData) Search(c cid.Cid) int {
	comm, err := commcid.CIDToPieceCommitmentV1(c)
	if err != nil {
		return -1
	}
	for i, e := range id.Entries {
		if bytes.Equal(e.CommDs[:], comm[:]) {
			return i
		}
	}
	return -1
}

// IndexSize returns the size of the index. Defined to be number of entries * 64 bytes
func (i IndexData) IndexSize() uint64 {
	return uint64(i.NumEntries()) * uint64(EntrySize)
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

// SegmentDesc contains a data segment description (v2 format)
// to be contained as four Fr32 elements in 4 leaf nodes of the data segment index
type SegmentDesc struct {
	// Commitment to the data segment (Merkle node which is the root of the subtree containing all the nodes making up the data segment)
	CommDs merkletree.Node
	// Offset is the offset from the start of the deal in pre-Fr32-padding bytes
	Offset uint64
	// Size is the number of pre-Fr32-padding bytes that is contained in the sub-deal (including padding)
	Size uint64
	// RawSize is the actual size of the meaningful data before any trailing padding (pre-Fr32-padding)
	RawSize uint64
	// Multicodec identifies the content encoding format (0x55 = Raw, 0x0202 = CAR)
	Multicodec uint64
	// MulticodecDependent is extension space for multicodec-specific metadata
	// For Raw and CAR codecs, this MUST be zero
	MulticodecDependent merkletree.Node
	// ACLType is the ACL type indicator (0 = no ACL, other values specified in future FRC)
	ACLType uint8
	// ACLData is ACL type-specific data (MUST be zero when ACLType is 0)
	ACLData uint64
	// Reserved is reserved for future versions of this FRC (MUST be zero in this version)
	Reserved [7]byte // 56 bits = 7 bytes
	// Checksum is a 126 bit checksum (SHA256) computed on all fields above with checksum bits set to zero
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

// UnpaddedOffest returns unpadded offset of the sub-deal relative to the deal start
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
		return xerrors.Errorf("invalid segment description size: expected %d, got %d", EntrySize, len(data))
	}
	le := binary.LittleEndian

	*sd = SegmentDesc{}
	// Node 1: CommDS (32 bytes)
	sd.CommDs = *(*merkletree.Node)(data[:merkletree.NodeSize])

	// Node 2: Offset (8 bytes) + NumEntries (8 bytes) + RawSize (8 bytes, but only 62 bits used) + Multicodec (8 bytes)
	offset := merkletree.NodeSize
	sd.Offset = le.Uint64(data[offset:])
	offset += 8
	sd.Size = le.Uint64(data[offset:])
	offset += 8
	sd.RawSize = le.Uint64(data[offset:]) & 0x3FFFFFFFFFFFFFFF // Mask to 62 bits
	offset += 8
	sd.Multicodec = le.Uint64(data[offset:])
	offset += 8

	// Node 3: MulticodecDependent (32 bytes)
	sd.MulticodecDependent = *(*merkletree.Node)(data[offset:])
	offset += merkletree.NodeSize

	// Node 4: ACLType (1 byte) + ACLData (8 bytes) + Reserved (7 bytes) + Checksum (16 bytes)
	sd.ACLType = data[offset]
	offset += 1
	sd.ACLData = le.Uint64(data[offset:])
	offset += 8
	copy(sd.Reserved[:], data[offset:offset+7])
	offset += 7
	copy(sd.Checksum[:], data[offset:offset+ChecksumSize])

	// Don't validate here - let the caller decide whether to validate
	// This allows unmarshaling invalid entries for testing purposes
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
	offset := 0

	// Node 1: CommDS (32 bytes)
	copy(slice[offset:], sd.CommDs[:])
	offset += merkletree.NodeSize

	// Node 2: Offset (8 bytes) + NumEntries (8 bytes) + RawSize (8 bytes, 62 bits used) + Multicodec (8 bytes)
	le.PutUint64(slice[offset:], sd.Offset)
	offset += 8
	le.PutUint64(slice[offset:], sd.Size)
	offset += 8
	// RawSize: only 62 bits, mask upper 2 bits
	le.PutUint64(slice[offset:], sd.RawSize&0x3FFFFFFFFFFFFFFF)
	offset += 8
	le.PutUint64(slice[offset:], sd.Multicodec)
	offset += 8

	// Node 3: MulticodecDependent (32 bytes)
	copy(slice[offset:], sd.MulticodecDependent[:])
	offset += merkletree.NodeSize

	// Node 4: ACLType (1 byte) + ACLData (8 bytes) + Reserved (7 bytes) + Checksum (16 bytes)
	slice[offset] = sd.ACLType
	offset += 1
	le.PutUint64(slice[offset:], sd.ACLData)
	offset += 8
	copy(slice[offset:], sd.Reserved[:])
	offset += 7
	copy(slice[offset:], sd.Checksum[:])
}

// IntoNodes converts the SegmentDesc directly into 4 Merkle nodes without intermediate allocation
// This avoids the overhead of SerializeFr32() which allocates a 256-byte buffer
func (sd SegmentDesc) IntoNodes() [4]merkletree.Node {
	var nodes [4]merkletree.Node
	le := binary.LittleEndian

	// Node 1: CommDS (32 bytes) - direct copy
	nodes[0] = sd.CommDs

	// Node 2: Offset (8) + Size (8) + RawSize (8, 62 bits) + Multicodec (8) = 32 bytes
	var node2 [32]byte
	le.PutUint64(node2[0:], sd.Offset)
	le.PutUint64(node2[8:], sd.Size)
	le.PutUint64(node2[16:], sd.RawSize&0x3FFFFFFFFFFFFFFF) // Mask to 62 bits
	le.PutUint64(node2[24:], sd.Multicodec)
	nodes[1] = merkletree.Node(node2)

	// Node 3: MulticodecDependent (32 bytes) - direct copy
	nodes[2] = sd.MulticodecDependent

	// Node 4: ACLType (1) + ACLData (8) + Reserved (7) + Checksum (16) = 32 bytes
	var node4 [32]byte
	node4[0] = sd.ACLType
	le.PutUint64(node4[1:], sd.ACLData)
	copy(node4[9:], sd.Reserved[:])
	copy(node4[16:], sd.Checksum[:])
	nodes[3] = merkletree.Node(node4)

	return nodes
}

func (sd SegmentDesc) Validate() error {
	// Validate checksum
	if sd.computeChecksum() != sd.Checksum {
		return validationError("computed checksum does not match embedded checksum")
	}

	// Validate RawSize <= NumEntries
	if sd.RawSize > sd.Size {
		return validationError("rawSize must be <= size")
	}

	// Validate Multicodec (must be supported: Raw or CAR)
	if sd.Multicodec != MulticodecRaw && sd.Multicodec != MulticodecCAR {
		return validationError("multicodec must be 0x55 (Raw) or 0x0202 (CAR)")
	}

	// Validate MulticodecDependent is zero for Raw and CAR codecs
	var zeroNode merkletree.Node
	if sd.MulticodecDependent != zeroNode {
		return validationError("multicodecDependent must be zero for Raw and CAR codecs")
	}

	// Validate ACLType and ACLData
	if sd.ACLType == 0 {
		if sd.ACLData != 0 {
			return validationError("aclData must be zero when aclType is 0")
		}
	}

	// Validate Reserved field is zero
	for i := range sd.Reserved {
		if sd.Reserved[i] != 0 {
			return validationError("reserved field must be zero")
		}
	}

	// Note: Offset and NumEntries alignment checks removed for v2 as flexible alignment is allowed
	// The specification recommends 127-byte alignment but allows arbitrary alignment

	return nil
}

// ==============================

// MakeNode converts SegmentDesc to 4 Merkle nodes
// Optimized to use IntoNodes() directly, avoiding intermediate buffer allocation
func (ds SegmentDesc) MakeNode() (merkletree.Node, merkletree.Node, merkletree.Node, merkletree.Node, error) {
	nodes := ds.IntoNodes()
	return nodes[0], nodes[1], nodes[2], nodes[3], nil
}
func MakeDataSegmentIdxWithChecksum(commDs *fr32.Fr32, offset uint64, size uint64, checksum *[ChecksumSize]byte) (SegmentDesc, error) {
	en := SegmentDesc{
		CommDs:              *(*merkletree.Node)(commDs),
		Offset:              offset,
		Size:                size,
		RawSize:             size, // Default to size if not specified (v1 compatibility)
		Multicodec:          MulticodecRaw,
		MulticodecDependent: merkletree.Node{},
		ACLType:             0,
		ACLData:             0,
		Reserved:            [7]byte{},
		Checksum:            *checksum,
	}
	if err := en.Validate(); err != nil {
		return SegmentDesc{}, xerrors.Errorf("input does not form a valid SegmentDesc: %w", err)
	}
	return en, nil
}

func MakeDataSegmentIndexEntry(CommP *fr32.Fr32, offset uint64, size uint64) (*SegmentDesc, error) {
	return MakeDataSegmentIndexEntryV2(CommP, offset, size, size, MulticodecRaw)
}

// MakeDataSegmentIndexEntryV2 creates a v2 index entry with all fields
func MakeDataSegmentIndexEntryV2(CommP *fr32.Fr32, offset uint64, size uint64, rawSize uint64, multicodec uint64) (*SegmentDesc, error) {
	en := SegmentDesc{
		CommDs:              *(*merkletree.Node)(CommP),
		Offset:              offset,
		Size:                size,
		RawSize:             rawSize,
		Multicodec:          multicodec,
		MulticodecDependent: merkletree.Node{},
		ACLType:             0,
		ACLData:             0,
		Reserved:            [7]byte{},
		Checksum:            [ChecksumSize]byte{},
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
	res := make([]merkletree.Node, 4*len(segments))
	curOffset := uint64(0)
	for i, segment := range segments {
		s := fr32.Fr32(segment)
		// TODO: fix segment desciption to be in bytes
		// XXX
		currentDesc, err := MakeDataSegmentIdx(&s, curOffset*merkletree.NodeSize, segmentSizes[i]*merkletree.NodeSize)
		if err != nil {
			return nil, err
		}
		// Use IntoNodes() directly for better performance
		nodes := currentDesc.IntoNodes()
		res[4*i] = nodes[0]
		res[4*i+1] = nodes[1]
		res[4*i+2] = nodes[2]
		res[4*i+3] = nodes[3]
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

// serializeFr32Entry is deprecated - use SerializeFr32Into directly instead
// This function is kept for backward compatibility but should not be used in new code
func serializeFr32Entry(buf *bytes.Buffer, entry *SegmentDesc) error {
	serialized := entry.SerializeFr32()
	_, err := buf.Write(serialized)
	if err != nil {
		return xerrors.Errorf("writing SegmentDesc: %w", err)
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
// Optimized to avoid intermediate allocations by directly writing to pre-allocated buffer
func serializeIndex(index *IndexData) ([]byte, error) {
	res := make([]byte, EntrySize*index.NumEntries())
	for i := 0; i < index.NumEntries(); i++ {
		index.Entry(i).SerializeFr32Into(res[i*EntrySize : (i+1)*EntrySize])
	}
	return res, nil
}

func validateIndexStructure(index *IndexData) error {
	if index == nil {
		return xerrors.Errorf("index is nil")
	}
	if index.NumEntries() <= 0 {
		return xerrors.Errorf("number of deal entries must be positive, %d < 0", index.NumEntries())
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
	return computeChecksumV2(commDs, offset, size, size, MulticodecRaw, merkletree.Node{}, 0, 0, [7]byte{})
}

// computeChecksumV2 computes checksum for v2 entry with all fields
func computeChecksumV2(commDs *merkletree.Node, offset uint64, size uint64, rawSize uint64, multicodec uint64, multicodecDependent merkletree.Node, aclType uint8, aclData uint64, reserved [7]byte) (*[ChecksumSize]byte, error) {
	tempEntry := SegmentDesc{
		CommDs:              *commDs,
		Offset:              offset,
		Size:                size,
		RawSize:             rawSize,
		Multicodec:          multicodec,
		MulticodecDependent: multicodecDependent,
		ACLType:             aclType,
		ACLData:             aclData,
		Reserved:            reserved,
		Checksum:            [ChecksumSize]byte{},
	}
	checkSum := tempEntry.computeChecksum()
	return &checkSum, nil
}

func validateChecksum(en *SegmentDesc) (bool, error) {
	refChecksum, err := computeChecksumV2(&(en.CommDs), en.Offset, en.Size, en.RawSize, en.Multicodec, en.MulticodecDependent, en.ACLType, en.ACLData, en.Reserved)
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
