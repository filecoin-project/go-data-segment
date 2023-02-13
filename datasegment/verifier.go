package datasegment

import (
	"github.com/filecoin-project/go-state-types/abi"
	"golang.org/x/xerrors"
)

type DataAggregationProof struct {
	Inclusion     InclusionProof
	AuxDataType   uint64 // always 0 for now
	AuxDataSource SingletonMarketSource
}

type SingletonMarketSource struct {
	DealID abi.DealID
}

type AuxDataFetch func(SingletonMarketSource) (InclusionAuxData, error)

// VerifyActive is the primary entrypoint for the verification routine
// auxDataResolver is de-factor call to the Market actor to fetch the aux data
func (dap DataAggregationProof) VerifyActive(verifierData InclusionVerifierData, auxDataFetch AuxDataFetch) error {
	auxData, err := auxDataFetch(dap.AuxDataSource)
	if err != nil {
		return xerrors.Errorf("aux data could not be fetched: %w", err)
	}
	if !auxData.DealActive {
		return xerrors.Errorf("the deal is not active")
	}
	return nil
}

func (dap DataAggregationProof) ComputeExpectedAuxData(verifierData InclusionVerifierData) (*InclusionAuxData, error) {
	return dap.Inclusion.ComputeExpectedAuxData(verifierData)
}
