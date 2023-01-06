package datasegment

import (
	"bytes"
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
	// Entry returns the entry in position of index. 0-indexed
	Entry(index int) Entry
}

type indexData struct {
	dealSize int
	entries  []Entry
}

func MakeIndex(entries []Entry, dealSize int) (Index, error) {
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

// Entry returns the entry in position of index. 0-indexed
func (i indexData) Entry(index int) Entry {
	return i.entries[index]
}

const entrySize int = fr32.BytesNeeded + 2*BytesInInt + BytesInChecksum

type Entry struct {
	CommDs fr32.Fr32
	Offset int
	Size   int
	Check  Checksum
}

type Checksum struct {
	Data [BytesInChecksum]byte
}

// serializeFr32Entry uses a buffer to serialize en entry into a byte slice
func serializeFr32Entry(buf *bytes.Buffer, entry Entry) error {
	err := binary.Write(buf, binary.LittleEndian, entry.CommDs.Data)
	if err != nil {
		log.Println("could not write the commitment of entry")
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(entry.Offset))
	if err != nil {
		log.Printf("could not write Offset %d of entry\n", entry.Offset)
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, uint64(entry.Size))
	if err != nil {
		log.Printf("could not write IndexSize %d of entry\n", entry.Size)
		return err
	}
	err = binary.Write(buf, binary.LittleEndian, entry.Check.Data)
	if err != nil {
		log.Println("could not write checksum of entry")
		return err
	}
	return nil
}

// SerializeIndex encodes a data segment Inclusion into a byte array
func SerializeIndex(index Index) ([]byte, error) {
	if !validateIndexStructure(index) {
		return nil, errors.New("the index is not valid")
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, uint64(index.DealSize()))
	if err != nil {
		log.Printf("could not write deal size %d\n", index.DealSize())
		return nil, err
	}
	for i := 0; i < index.NumberEntries(); i++ {
		err = serializeFr32Entry(buf, index.Entry(i))
		if err != nil {
			log.Printf("could not write entry %d\n", i)
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// deserializeFr32Entry deserializes a byte slice into an Entry
func deserializeFr32Entry(encoded []byte) (Entry, error) {
	if len(encoded) != entrySize {
		log.Println("no entry encoded")
		return Entry{}, errors.New("no entry encoded")
	}
	ctr := 0
	commDs := (*[fr32.BytesNeeded]byte)(encoded[ctr : ctr+fr32.BytesNeeded])
	ctr += fr32.BytesNeeded
	offset := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	size := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	checksum := (*[BytesInChecksum]byte)(encoded[ctr : ctr+BytesInChecksum])
	ctr += BytesInChecksum
	entry := Entry{
		CommDs: fr32.Fr32{Data: *commDs},
		Offset: offset,
		Size:   size,
		Check:  Checksum{Data: *checksum},
	}
	return entry, nil
}

// DeserializeIndex decodes a byte array into a data segment Index
// Assumes the index is FR32 padded
func DeserializeIndex(encoded []byte) (Index, error) {
	// Check that at least one Entry is included and that the size is appropriate
	if encoded == nil || len(encoded) < minIndexSize || (len(encoded)-minIndexSize)%entrySize != 0 {
		log.Println("no legal data segment index encoding")
		return nil, errors.New("no legal data segment index encoding")
	}
	entries := len(encoded) / entrySize
	decoded := make([]Entry, entries)
	ctr := 0
	dealSize := int(binary.LittleEndian.Uint64(encoded[ctr : ctr+BytesInInt]))
	ctr += BytesInInt
	for i := 0; i < entries; i++ {
		var err error
		decoded[i], err = deserializeFr32Entry(encoded[ctr : ctr+entrySize])
		if err != nil {
			log.Printf("could not deserialize entry %d\n", i)
			return nil, err
		}
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
		if index.Entry(i).Size < 0 {
			log.Printf("size in entry %d is %d, it must not be negative\n", i, index.Entry(i).Size)
			return false
		}
		if index.Entry(i).Offset < 0 {
			log.Printf("offset in entry %d is %d, it must not be negative\n", i, index.Entry(i).Offset)
			return false
		}
	}
	return true
}
