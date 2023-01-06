package datasegment

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/filecoin-project/go-data-segment/fr32"
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
	// Entry returns the Entry in position of index. 0-indexed
	Entry(index int) *Entry
}

type indexData struct {
	dealSize int
	entries  []*Entry
}

func MakeIndex(entries []*Entry, dealSize int) (Index, error) {
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

// Entry returns the Entry in position of index. 0-indexed
func (i indexData) Entry(index int) *Entry {
	return i.entries[index]
}

const entrySize int = fr32.BytesNeeded + 2*BytesInInt + BytesInChecksum

type Entry struct {
	CommDs   fr32.Fr32
	Offset   int
	Size     int
	Checksum [BytesInChecksum]byte
}

func MakeEntryWithChecksum(commDs *fr32.Fr32, offset int, size int, checksum *[BytesInChecksum]byte) (*Entry, error) {
	en := Entry{
		CommDs:   *commDs,
		Offset:   offset,
		Size:     size,
		Checksum: *checksum,
	}
	if !validateEntry(&en) {
		return nil, errors.New("input does not form a valid Entry")
	}
	return &en, nil
}

func MakeEntry(commDs *fr32.Fr32, offset int, size int) (*Entry, error) {
	checksum, err := computeChecksum(commDs, offset, size)
	if err != nil {
		log.Println("could not compute checksum")
		return nil, err
	}
	return MakeEntryWithChecksum(commDs, offset, size, checksum)
}

// serializeFr32Entry uses a buffer to serialize en Entry into a byte slice
func serializeFr32Entry(buf *bytes.Buffer, entry *Entry) error {
	err := binary.Write(buf, binary.LittleEndian, entry.CommDs.Data)
	if err != nil {
		log.Println("could not write the commitment of Entry")
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(entry.Offset))
	if err != nil {
		log.Printf("could not write Offset %d of Entry\n", entry.Offset)
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(entry.Size))
	if err != nil {
		log.Printf("could not write IndexSize %d of Entry\n", entry.Size)
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, entry.Checksum)
	if err != nil {
		log.Println("could not write checksum of Entry")
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
		err = serializeFr32Entry(buf, index.Entry(i))
		if err != nil {
			log.Printf("could not write Entry %d\n", i)
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// deserializeFr32Entry deserializes a byte slice into an Entry
func deserializeFr32Entry(encoded []byte) *Entry {
	ctr := 0
	commDs := (*[fr32.BytesNeeded]byte)(encoded[ctr : ctr+fr32.BytesNeeded])
	ctr += fr32.BytesNeeded
	offset := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	size := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	checksum := *(*[BytesInChecksum]byte)(encoded[ctr : ctr+BytesInChecksum])
	ctr += BytesInChecksum
	en := Entry{
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
	// Check that at least one Entry is included and that the size is appropriate
	if encoded == nil || len(encoded) < minIndexSize || (len(encoded)-minIndexSize)%entrySize != 0 {
		log.Println("no legal data segment index encoding")
		return nil, errors.New("no legal data segment index encoding")
	}
	index, err := deserializeIndex(encoded)
	if err != nil {
		log.Println("could not deserialize index")
		return nil, err
	}
	if !validateIndexStructure(index) {
		log.Println("deserialized structure is not valid")
		return nil, err
	}
	return index, nil
}

// deserializeIndex decodes a byte array into a data segment Index, without any validation
// Assumes the index is FR32 padded
func deserializeIndex(encoded []byte) (Index, error) {
	entries := len(encoded) / entrySize
	decoded := make([]*Entry, entries)
	ctr := 0
	dealSize := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	for i := 0; i < entries; i++ {
		decoded[i] = deserializeFr32Entry(encoded[ctr : ctr+entrySize])
		ctr += entrySize
	}
	return indexData{dealSize: dealSize, entries: decoded}, nil
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
		if !validateEntry(index.Entry(i)) {
			return false
		}
	}
	return true
}

func validateEntry(en *Entry) bool {
	if en.Size < 0 {
		log.Printf("size in Entry is %d, it must not be negative\n", en.Size)
		return false
	}
	if en.Offset < 0 {
		log.Printf("offset in Entry is %d, it must not be negative\n", en.Offset)
		return false
	}
	return validateChecksum(en)
}

func computeChecksum(commDs *fr32.Fr32, offset int, size int) (*[BytesInChecksum]byte, error) {
	buf := new(bytes.Buffer)
	tempEntry := Entry{
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
	// We want to hash the Entry, excluding the computeChecksum as it is what we are trying to compute
	toHash := buf.Bytes()[:fr32.BytesNeeded+2*BytesInInt]
	digest := sha256.Sum256(toHash)
	res := digest[:BytesInChecksum]
	// Reduce the size to 126 bits
	res[BytesInChecksum-1] &= 0b00111111
	return (*[BytesInChecksum]byte)(res), nil
}

func validateChecksum(en *Entry) bool {
	refChecksum, err := computeChecksum(&(en.CommDs), en.Offset, en.Size)
	if err != nil {
		log.Println("could not serialize Entry")
		return false
	}
	if !bytes.Equal(refChecksum[:], en.Checksum[:]) {
		return false
	}
	return true
}
