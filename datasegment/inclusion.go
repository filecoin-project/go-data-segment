package datasegment

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
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

// Validate verifies that the commitment to a user's data segment, commDs, is included correctly in the inclusion tree.
// I.e. both the inclusion in the deal tree is verified, along with the inclusion in the index (sub) tree.
// The method also validates the position of the index and depths in relation to the size of the data segment.
// commDs is the commitment to the user's data segment. I.e. a node in the deal tree, where the leafs of its subtree contains all the nodes in the user's data segment
// commDA is the commitment of the aggregator, i.e. the root of the inclusion tree
// sizeDs is the amount of nodes included in the client's data segment.
// sizeDA is the amount of nodes included in the deal of the aggregator
// segments is the amount of client data segments included in the deal
// proofSubtree is the proof that the client's
func Validate(commDs *fr32.Fr32, sizeDs uint64, commDA *fr32.Fr32, sizeDA uint64, segments int, proofSubtree merkletree.MerkleProof, proofDs merkletree.MerkleProof) bool {
	// Validate the whole subtree is actually included
	if !verifySegmentInclusion(segments, sizeDA, sizeDs, proofSubtree.Level()) {
		return false
	}
	// Validate subtree inclusion
	if !VerifyInclusion(commDs, commDA, proofSubtree) {
		return false
	}
	// Compute how far to the leaf level in the inc tree we must go to find the first segment, being covered by proofSubtree
	// The amount of levels in the inclusion tree is proofDs.Level() + 1 thus the amount of doubling of proofSubtree.Index()
	// that is needed to get to the first leaf position is (proofDs.Level() + 1) - proofSubtree.Level()
	leafIdx := uint64(proofSubtree.Index()) << ((proofDs.Level() + 1) - proofSubtree.Level())
	index, err := MakeDataSegmentIdx(commDs, leafIdx, sizeDs)
	if err != nil {
		log.Println("could not construct data segment index")
		return false
	}
	if !VerifySegDescInclusion(index, commDA, sizeDA, segments, proofDs) {
		return false
	}
	return true
}

// verifySegmentInclusion checks that the proof subtree is actually of correct depth when taking into account the size
// of the data segment and the amount of segments included in the deal.
// TODO is this actually needed or implicitly assumed that the network checks the merkle tree is correct? Because we need more of the tree to validate this
func verifySegmentInclusion(segments int, sizeDA uint64, sizeDs uint64, proofLvl int) bool {
	// Compute the expected amount of leaf nodes
	incLeafs := computeIncTreeLeafs(segments, sizeDA)
	segmentDepth := util.Log2Ceil(uint64(sizeDs))
	return util.Log2Ceil(uint64(incLeafs)) == segmentDepth+proofLvl
}

// VerifyInclusion validates a commitment, comm, in accordance to a proof to a root of a tree
func VerifyInclusion(comm *fr32.Fr32, root *fr32.Fr32, proof merkletree.MerkleProof) bool {
	element := merkletree.Node{Data: comm.Data}
	rootNode := merkletree.Node{Data: root.Data}
	return proof.ValidateSubtree(&element, &rootNode)
}

// VerifySegDescInclusion validates that a data segment index, segDesc, has been included in the index (sub) tree, proofDs
// and verifies that the position in the index tree is correct according to the amount of data segments included in the deal and the total size of the deal
// segDesc is the data segment index to validate.
// sizeDA is the amount of 32 byte notes included in the entire deal
// segments is the amount of client data segments included in the deal
// proofDs is the Merkle proof of index inclusion in the inclusion tree to validate
func VerifySegDescInclusion(segDesc *SegmentDescIdx, commDA *fr32.Fr32, sizeDA uint64, segments int, proofDs merkletree.MerkleProof) bool {
	if !validateIndexTreePos(sizeDA, segments, proofDs) {
		return false
	}
	buf := new(bytes.Buffer)
	err := serializeFr32Entry(buf, segDesc)
	if err != nil {
		log.Println("could not serialize segDesc")
		return false
	}
	toHash := buf.Bytes()
	comm := fr32.Fr32{Data: merkletree.TruncatedHash(toHash).Data}
	return VerifyInclusion(&comm, commDA, proofDs)
}

// MakeInclusionTree constructs an inclusion tree based on the deal tree and a list of the nodes that contain all the client segments
func MakeInclusionTree(segments []merkletree.Node, segmentSizes []uint64, dealTree merkletree.MerkleTree) (merkletree.MerkleTree, error) {
	newCapacity := computeIncTreeLeafs(len(segments), uint64(len(dealTree.Leafs())))
	// Make a new leaf level
	combinedLeafs := make([]merkletree.Node, newCapacity)
	// And add the old leafs
	copy(combinedLeafs, dealTree.Leafs())
	segDescs, err := MakeSegDescs(segments, segmentSizes)
	if err != nil {
		return nil, err
	}
	// And copy the index leafs to the positions of the right-most subtree that can contain them
	start := indexStart(len(segments), uint64(len(dealTree.Leafs())))
	copy(combinedLeafs[start:], segDescs)
	return merkletree.GrowTreeHashedLeafs(combinedLeafs), nil
}

// MakeIndexProof constructs a data segment proof to the index of the data segment with a given offset in the deal tree
func MakeIndexProof(inclusionTree merkletree.MerkleTree, segmentIdx uint64, sizeDA uint64, segments int) (merkletree.MerkleProof, error) {
	// The node we want to prove membership of is one level above the leafs in the index tree
	lvl := inclusionTree.Depth() - 2
	idx := (indexStart(segments, sizeDA) >> 1) + segmentIdx
	return inclusionTree.ConstructProof(lvl, idx)
}

// indexStart computes the leaf where the first data segment index should be placed
func indexStart(segments int, sizeDA uint64) uint64 {
	// Compute the amount of total leafs in the tree including the index
	inclusionCapacity := computeIncTreeLeafs(segments, sizeDA)
	// Compute the size of the index. 2-power to ensure it is a proper subtree. Each segment requires two leaf nodes in the index
	indexAlign := uint64(1) << util.Log2Ceil(uint64(2*segments))
	// Index is places in the rightmost and smallest subtree it requires
	return inclusionCapacity - indexAlign
}

// computeIncTreeLeafs computes the amount of leafs needed in an inclusion tree based on the amount of segments and the amount of 32 byte data elements, sizeDA
func computeIncTreeLeafs(segments int, sizeDA uint64) uint64 {
	// Compute the size of subtree we need for the index, which needs 2 nodes per deal
	indexTreeLeafs := uint64(1) << util.Log2Ceil(uint64(2*segments))
	return 1 << util.Log2Ceil(sizeDA+indexTreeLeafs)
}

// validateIndexTreePos validates the position of a data segment index in an index (sub) tree, proofDs
// sizeDA is the amount of 32 byte nodes in the entire deal.
// segments is the total amount of segments included in the deal
// proofDs is the data segment index proof
func validateIndexTreePos(sizeDA uint64, segments int, proofDs merkletree.MerkleProof) bool {
	// Validate the level in the index tree
	incTreeDepth := 1 + util.Log2Ceil(uint64(computeIncTreeLeafs(segments, sizeDA)))
	// Check that the proof of the commitment is one level above the leafs, when levels are 0-indexed
	return proofDs.Level() == incTreeDepth-2
}
