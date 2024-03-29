package datasegment

import (
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

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

	enNode := merkletree.TruncatedHash(en.SerializeFr32())

	assumedCommPa2, err := ip.ProofIndex.ComputeRoot(enNode)
	if err != nil {
		return nil, xerrors.Errorf("could not validate the index proof: %w", err)
	}

	if *assumedCommPa != *assumedCommPa2 {
		return nil, xerrors.Errorf("aggregator's data commiements don't match: %x != %x", assumedCommPa, assumedCommPa2)
	}

	const BytesInDataSegmentIndexEntry = 2 * merkletree.NodeSize

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
	dsProof, err := ht.CollectProof(1, iAS/EntrySize+uint64(indexEntry))
	if err != nil {
		return nil, xerrors.Errorf("collecting subtree proof: %w", err)
	}

	return &InclusionProof{ProofSubtree: subTreeProof, ProofIndex: dsProof}, nil
}

// VerifierDataForPieceInfo returns information provided by the verifier based on PieceInfo
func VerifierDataForPieceInfo(pi abi.PieceInfo) InclusionVerifierData {
	return InclusionVerifierData{
		CommPc: pi.PieceCID, SizePc: pi.Size,
	}
}
