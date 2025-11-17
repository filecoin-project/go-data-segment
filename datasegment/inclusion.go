package datasegment

import (
	"crypto/sha256"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

// computeEntryNode computes a Merkle tree node from two child nodes
// This is the same logic as merkletree.computeNode but we need it here
// since computeNode is not exported
func computeEntryNode(left *merkletree.Node, right *merkletree.Node) *merkletree.Node {
	sha := sha256.New()
	sha.Write(left[:])
	sha.Write(right[:])
	digest := sha.Sum(nil)
	node := merkletree.Node(digest)
	// Truncate the last 2 bits (same as merkletree.truncate)
	node[merkletree.NodeSize-1] &= 0b00111111
	return &node
}

const BytesInInt = 8

// InclusionVerifierData is the information required for verification of the proof and is sourced
// from the client.
type InclusionVerifierData struct {
	// Piece Commitment to client's data
	CommPc cid.Cid
	// SizePc is size of client's data
	SizePc abi.PaddedPieceSize
}

// InclusionAuxData is required for verification of the proof and needs to be cross-checked with the chain state
type InclusionAuxData struct {
	// Piece Commitment to aggregator's deal
	CommPa cid.Cid
	// SizePa is padded size of aggregator's deal
	SizePa abi.PaddedPieceSize
}

// InclusionPoof is produced by the aggregator (or possibly by the SP)
type InclusionProof struct {
	// ProofSubtree is proof of inclusion of the client's data segment in the data aggregator's Merkle tree (includes position information)
	// I.e. a proof that the root node of the subtree containing all the nodes (leafs) of a data segment is contained in CommDA
	ProofSubtree merkletree.ProofData
	// ProofIndex is a proof that an entry for the user's data is contained in the index of the aggregator's deal.
	// I.e. a proof that the data segment index constructed from the root of the user's data segment subtree is contained in the index of the deal tree.
	ProofIndex merkletree.ProofData
}

func indexAreaStart(sizePa abi.PaddedPieceSize) uint64 {
	return uint64(sizePa) - uint64(MaxIndexEntriesInDeal(sizePa))*uint64(EntrySize)
}

func (ip InclusionProof) ComputeExpectedAuxData(veriferData InclusionVerifierData) (*InclusionAuxData, error) {
	// Verification flow:
	//  1. Varify inputs
	//	2. Decode Client's Piece commitment
	//	3. Compute assumed aggregator's commitment based on the subtree inclusion proof
	//	4. Compute size of aggregator's deal and offset of Client's deal within the Aggreggator's deal.
	//	5. Create the DataSegmentIndexEntry based on Client's data and offset from 3
	//	6. Compute second assumed aggregator's commitment based on the data segment index entry inclusion proof.
	//  7. Check if DataSegmentIndexEntry falls into the correct area.
	//	8. Compute second assumed aggregator's deal size.
	//	9. Compare deal sizes and commitments from steps 2+3 against steps 5+6. Fail if not equal.
	//	10. Return the computed values of aggregator's Commitment and Size as AuxData.

	if !util.IsPow2(uint64(veriferData.SizePc)) {
		return nil, xerrors.Errorf("size of piece provided by verifier is not power of two")
	}

	commPc, err := lightCid2CommP(veriferData.CommPc)
	if err != nil {
		return nil, xerrors.Errorf("invalid piece commitment: %w", err)
	}
	nodeCommPc := (merkletree.Node)(commPc)

	// Compute the Commitment to aggregator's data and assume it is correct
	// we will cross validate it against the other proof and then return it for futher validation
	assumedCommPa, err := ip.ProofSubtree.ComputeRoot(&nodeCommPc)
	if err != nil {
		return nil, xerrors.Errorf("could not validate the subtree proof: %w", err)
	}

	var assumedSizePa abi.PaddedPieceSize
	{
		assumedSizePau64, ok := util.CheckedMultiply(uint64(1)<<ip.ProofSubtree.Depth(), uint64(veriferData.SizePc))
		if !ok {
			return nil, xerrors.Errorf("assumedSizePa overflow")
		}
		assumedSizePa = abi.PaddedPieceSize(assumedSizePau64)
	}

	// inclusion proof verification checks that index is less than the 1<<(path length)
	dataOffset := ip.ProofSubtree.Index * uint64(veriferData.SizePc)

	en, err := MakeDataSegmentIndexEntry((*fr32.Fr32)(&nodeCommPc), dataOffset, uint64(veriferData.SizePc))
	if err != nil {
		return nil, xerrors.Errorf("createding data segment index entry: %w", err)
	}

	// In v2, each index entry consists of 4 nodes
	// We need to compute the Merkle root of these 4 nodes
	// The 4 nodes form a small tree:
	//   Level 0: n0, n1, n2, n3
	//   Level 1: hash(n0, n1), hash(n2, n3)
	//   Level 2: hash(hash(n0, n1), hash(n2, n3))
	entryNodes := en.IntoNodes()
	// Compute level 1: hash pairs (same as merkletree.computeNode)
	level1Left := computeEntryNode(&entryNodes[0], &entryNodes[1])
	level1Right := computeEntryNode(&entryNodes[2], &entryNodes[3])
	// Compute level 2 (root): hash the two level-1 nodes
	enNode := computeEntryNode(level1Left, level1Right)

	// The proof is collected for the root of the 4-node entry subtree (level 2)
	assumedCommPa2, err := ip.ProofIndex.ComputeRoot(enNode)
	if err != nil {
		return nil, xerrors.Errorf("could not validate the index proof: %w", err)
	}

	if *assumedCommPa != *assumedCommPa2 {
		return nil, xerrors.Errorf("aggregator's data commiements don't match: %x != %x", assumedCommPa, assumedCommPa2)
	}

	const BytesInDataSegmentIndexEntry = 4 * merkletree.NodeSize // v2: 4 nodes per entry

	var assumedSizePa2 abi.PaddedPieceSize
	{
		assumedSizePau64, ok := util.CheckedMultiply(uint64(1)<<ip.ProofIndex.Depth(), BytesInDataSegmentIndexEntry)
		if !ok {
			return nil, xerrors.Errorf("assumedSizePa2 overflow")
		}
		assumedSizePa2 = abi.PaddedPieceSize(assumedSizePau64)
	}

	if assumedSizePa2 != assumedSizePa {
		return nil, xerrors.Errorf("aggregator's data size doesn't match")
	}

	idxStart := indexAreaStart(assumedSizePa2)
	indexOffset, ok := util.CheckedMultiply(ip.ProofIndex.Index, BytesInDataSegmentIndexEntry)
	if !ok {
		return nil, xerrors.Errorf("indexOffset overflow")
	}
	if indexOffset < idxStart {
		return nil, xerrors.Errorf("index entry at wrong position: %d < %d",
			ip.ProofIndex.Index*uint64(EntrySize), idxStart)
	}

	cidPa, err := lightCommP2Cid(*assumedCommPa)
	if err != nil {
		return nil, xerrors.Errorf("converting raw commiement to CID: %w", err)
	}

	return &InclusionAuxData{
		CommPa: cidPa,
		SizePa: assumedSizePa,
	}, nil
}

func CollectInclusionProof(ht *merkletree.Hybrid, dealSize abi.PaddedPieceSize, pieceInfo merkletree.CommAndLoc, indexEntry int) (*InclusionProof, error) {
	subTreeProof, err := ht.CollectProof(pieceInfo.Loc.Level, pieceInfo.Loc.Index)
	if err != nil {
		return nil, xerrors.Errorf("collecting subtree proof: %w", err)
	}

	iAS := indexAreaStart(dealSize)
	entryNodeIndex := iAS/merkletree.NodeSize + 4*uint64(indexEntry) // 4 nodes per entry
	// In v2, each entry consists of 4 nodes forming a small subtree
	// We need to collect proof for the root of this 4-node subtree
	// The root is at level 2 with index = entryNodeIndex / 4
	entryRootLevel := 2
	entryRootIndex := entryNodeIndex / 4
	dsProof, err := ht.CollectProof(entryRootLevel, entryRootIndex)
	if err != nil {
		return nil, xerrors.Errorf("collecting index entry proof: %w", err)
	}

	return &InclusionProof{ProofSubtree: subTreeProof, ProofIndex: dsProof}, nil
}

// VerifierDataForPieceInfo returns information provided by the verifier based on PieceInfo
func VerifierDataForPieceInfo(pi abi.PieceInfo) InclusionVerifierData {
	return InclusionVerifierData{
		CommPc: pi.PieceCID, SizePc: pi.Size,
	}
}
