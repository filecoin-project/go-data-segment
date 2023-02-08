package datasegment

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	"golang.org/x/xerrors"
)

// We use the terminology "deal Tree" to define the tree of actual data being stored by the aggregator in a deal.
// I.e. its leafs contain all the client's data segments.
// We use the terminology "index tree" to mean the small (sub) tree which contains all the data segment indices of the client's data segments in its leafs.
// This tree will have leafs equal to 2 times the amount of data segments included in the deal tree, since a data segment description requires two nodes.
// We use the term "inclusion tree" to mean the tree encompassing both the deals and the index tree. The index tree will be stored in the right-most position possible
// where it will still be a properly aligned subtree. I.e. in the right-most corner of the inclusion tree,
// but potentially with some empty leafs (to the right) in case the amount of data segments in the deal tree is not a 2-power

// BytesInInt represents the amount of bytes used to encode an int
const BytesInInt int = 64 / 8
const BytesInNode = fr32.BytesNeeded

// 3 integers includes the IndexSize of the aggregator's data and the size of the two Merkle proofs
const minSizeInclusion int = fr32.BytesNeeded + 3*BytesInInt

// Inclusion is a proof of a client's data segment being included in a deal.
type Inclusion struct {
	// CommDA is a commitment of the aggregator's deal (the root of the deal tree)
	CommDA fr32.Fr32
	// Size of the aggregator's data in nodes (leafs). The total amount of bytes is Size*32
	Size int
	// ProofSubtree is proof of inclusion of the client's data segment in the data aggregator's Merkle tree (includes position information)
	// I.e. a proof that the root node of the subtree containing all the nodes (leafs) of a data segment is contained in CommDA
	ProofSubtree merkletree.MerkleProof
	// ProofDs is a proof that the user's data segment is contained in the index of the aggregator's deal.
	// I.e. a proof that the data segment index constructed from the root of the user's data segment subtree is contained in the index of the deal tree.
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
	if len(encoded) < minSizeInclusion {
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
		CommDA:       *(*fr32.Fr32)(commDA),
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

// Validate verifies that the commitment to a user's data segment, commDs, is included correctly in the inclusion tree.
// I.e. both the inclusion in the deal tree is verified, along with the inclusion in the index (sub) tree.
// The method also validates the position of the index and depths in relation to the size of the data segment.
// commDs is the commitment to the user's data segment. I.e. a node in the deal tree, where the leafs of its subtree contains all the nodes in the user's data segment
// commDA is the commitment of the aggregator, i.e. the root of the inclusion tree
// sizeDs is the amount of nodes included in the client's data segment.
// sizeDA is the amount of nodes included in the deal of the aggregator
// segments is the number of client data segments included in the deal
// proofSubtree is the proof that the client's
func Validate(commDs *fr32.Fr32, sizeDs uint64, commDA *fr32.Fr32, sizeDA uint64, proofSubtree merkletree.MerkleProof, proofDs merkletree.MerkleProof) error {
	// Validate the whole subtree is actually included
	if err := verifySegmentInclusion(sizeDA, sizeDs, proofSubtree); err != nil {
		return xerrors.Errorf("verifySegmentInclusion: %w", err)
	}
	// Validate subtree inclusion
	if err := VerifyInclusion(commDs, commDA, proofSubtree); err != nil {
		return xerrors.Errorf("failed to verify inclusion of the subtree: %w", err)
	}
	// Compute how far to the leaf level in the inc tree we must go to find the first segment, being covered by proofSubtree
	// The amount of levels in the inclusion tree is proofDs.Level() + 1 thus the amount of doubling of proofSubtree.Index()
	// that is needed to get to the first leaf position is (proofDs.Level() + 1) - proofSubtree.Level()
	leafIdx := uint64(proofSubtree.Index()) << ((proofDs.Depth() + 1) - proofSubtree.Depth())
	index, err := MakeDataSegmentIdx(commDs, leafIdx, sizeDs)
	if err != nil {
		return xerrors.Errorf("making data-segment index entry: %w", err)
	}
	if err := VerifySegDescInclusion(index, commDA, sizeDA, proofDs); err != nil {
		return xerrors.Errorf("veriying segment descriptor inclusion: %w", err)
	}
	return nil
}

// verifySegmentInclusion checks that the proof subtree is actually of correct depth when taking into account the size
// of the data segment.
// TODO is this actually needed or implicitly assumed that the network checks the merkle tree is correct? Because we need more of the tree to validate this
func verifySegmentInclusion(sizeDA uint64, sizeDs uint64, proof merkletree.MerkleProof) error {
	proofLvl := proof.Depth()
	// TODO validate that the deal containes the whole semgnet
	// Compute the expected amount of leaf nodes
	segmentDepth := util.Log2Ceil(uint64(sizeDs))
	if util.Log2Ceil(sizeDA) != segmentDepth+proofLvl {
		return xerrors.Errorf("segment size and proof length incorrect: %d != %d", util.Log2Ceil(sizeDA), segmentDepth+proofLvl)
	}
	return nil
}

// VerifyInclusion validates a commitment, comm, in accordance to a proof to a root of a tree
func VerifyInclusion(comm *fr32.Fr32, root *fr32.Fr32, proof merkletree.MerkleProof) error {
	element := merkletree.Node(*comm)
	rootNode := merkletree.Node(*root)
	return proof.ValidateSubtree(&element, &rootNode)
}

// VerifySegDescInclusion validates that a data segment index, segDesc, has been included in the index (sub) tree, proofDs
// and verifies that the position in the index tree is correct according to the amount of data segments included in the deal and the total size of the deal
// segDesc is the data segment index to validate.
// sizeDA is the amount of 32 byte notes included in the entire deal
// segments is the amount of client data segments included in the deal
// proofDs is the Merkle proof of index inclusion in the inclusion tree to validate
func VerifySegDescInclusion(segDesc *SegmentDescIdx, commDA *fr32.Fr32, sizeDA uint64, proofDs merkletree.MerkleProof) error {
	if err := validateIndexTreePos(sizeDA, proofDs); err != nil {
		return xerrors.Errorf("validate index tree position: %w", err)
	}
	buf := new(bytes.Buffer)
	err := serializeFr32Entry(buf, segDesc)
	if err != nil {
		return xerrors.Errorf("could not serialise segment desciptior: %w", err)
	}
	toHash := buf.Bytes()
	comm := fr32.Fr32(*merkletree.TruncatedHash(toHash))
	return VerifyInclusion(&comm, commDA, proofDs)
}

// MakeInclusionTree constructs an inclusion tree based on the deal tree and a list of the nodes that contain all the client segments, returns also the starting offset of the index
func MakeInclusionTree(segments []merkletree.Node, segmentSizes []uint64, dealTree merkletree.MerkleTree) (merkletree.MerkleTree, uint64, error) {
	indexStart, indexSize := placeIndex(len(segments), dealTree.LeafCount())
	newCapacity := indexStart + indexSize
	// Make a new leaf level
	combinedLeafs := make([]merkletree.Node, newCapacity)
	// And add the old leafs
	copy(combinedLeafs, dealTree.Leafs())
	segDescs, err := MakeSegDescs(segments, segmentSizes)
	if err != nil {
		return nil, 0, err
	}
	// And copy the index leafs to the positions of the right-most subtree that can contain them
	copy(combinedLeafs[indexStart:], segDescs)
	return merkletree.GrowTreeHashedLeafs(combinedLeafs), indexStart, nil
}

// MakeIndexProof constructs a data segment proof to the index of the data segment with a given offset in the deal tree
func MakeIndexProof(inclusionTree merkletree.MerkleTree, segmentIdx uint64, indexStart uint64) (merkletree.MerkleProof, error) {
	// The node we want to prove membership of is one level above the leafs in the index tree
	lvl := inclusionTree.Depth() - 2
	idx := indexStart/2 + segmentIdx
	return inclusionTree.ConstructProof(lvl, idx)
}

// placeIndex returns where the index should start to be written and its size
func placeIndex(segments int, dataOnlySize uint64) (start uint64, size uint64) {
	sizeOfIndex := uint64(1) << util.Log2Ceil(2*uint64(segments))
	// pad data to the sizeOfIndex such that sizeOfIndex begins at power of two
	dataOnlySizePadded := dataOnlySize + (sizeOfIndex - dataOnlySize%sizeOfIndex)
	return dataOnlySizePadded, sizeOfIndex
}

//lint:ignore U1000 WIP
func indexAreaStart(sizeDA uint64) uint64 {
	return sizeDA - uint64(MaxIndexEntriesInDeal(sizeDA*BytesInNode))*2
}

// validateIndexTreePos validates the position of a data segment index in an index (sub) tree, proofDs
// sizeDA is the amount of 32 byte nodes in the entire deal.
// segments is the total amount of segments included in the deal
// proofDs is the data segment index proof
func validateIndexTreePos(sizeDA uint64, proofDs merkletree.MerkleProof) error {
	// Validate the level in the index tree
	// Check that the proof of the commitment is one level above the leafs, when levels are 0-indexed
	if proofDs.Depth() != 1+util.Log2Ceil(sizeDA)-2 {
		return xerrors.Errorf("data segment inclusion proof leads to wrong level: %d != %d", proofDs.Depth(), 1+util.Log2Ceil(sizeDA)-1)
	}
	return nil
}
