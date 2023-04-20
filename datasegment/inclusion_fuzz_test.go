package datasegment

import (
	"testing"

	abi "github.com/filecoin-project/go-state-types/abi"
)

// FuzzInclusionProofSizes takes in a valid proof and tries to find another one which passed with
// different sizes, offsets so on.
func FuzzInclusionProofSizes(f *testing.F) {
	verifData, incProof, expectedAux := InclusionGolden1()
	f.Logf("Orginal: %d, %d, %d, %d", verifData.SizePc, incProof.ProofIndex.Index,
		incProof.ProofSubtree.Index, expectedAux.SizePa)
	add := func(sizePc, indexProofIndex, subtreeProofIndex, sizePa uint64) {
		f.Add(sizePc, indexProofIndex, subtreeProofIndex, sizePa)
	}

	add(uint64(verifData.SizePc), incProof.ProofIndex.Index,
		incProof.ProofSubtree.Index, uint64(expectedAux.SizePa))
	// augmented initial corpus based on fuzzing
	add(536870912, 536608771, 84, 34359738413)
	add(536870826, 536608771, 5, 34359738368)
	add(536870912, 536608767, 63, 34359738193)
	add(536870912, 536608771, 2, 34359738368)
	add(536870912, 536608715, 5, 34359738368)

	f.Fuzz(func(t *testing.T, newSizePc, newIndexProofIndex, newSubtreeProofIndex, newSizePa uint64) {
		t.Logf("New: %d, %d, %d, %d", newSizePc, newIndexProofIndex, newSubtreeProofIndex, newSizePa)
		newVerifData, newIncProof, newExpectedAux := verifData, incProof, expectedAux
		newVerifData.SizePc = abi.PaddedPieceSize(newSizePc)
		newIncProof.ProofIndex.Index = newIndexProofIndex
		newIncProof.ProofSubtree.Index = newSubtreeProofIndex
		newExpectedAux.SizePa = abi.PaddedPieceSize(newSizePa)

		computedAux, err := newIncProof.ComputeExpectedAuxData(newVerifData)
		if err != nil {
			return
		}
		if *computedAux == newExpectedAux {
			if verifData != newVerifData || incProof.ProofIndex.Index != newIncProof.ProofIndex.Index ||
				incProof.ProofSubtree.Index != newIncProof.ProofSubtree.Index {
				t.Fatalf("new matching aux data with the same proof")
			}
		}
	})
}
