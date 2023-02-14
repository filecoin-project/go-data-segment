package datasegment

import (
	"github.com/filecoin-project/go-state-types/abi"
	"golang.org/x/xerrors"
)

// DataAggregationProof is the top level proof structure provided by the aggregator
// after the deal lands on chain.
type DataAggregationProof struct {
	Inclusion     InclusionProof
	AuxDataType   uint64 // always 0 for now
	AuxDataSource SingletonMarketSource
}

type SingletonMarketSource struct {
	DealID abi.DealID
}

type SingletonMarketAuxData struct {
	DealActive bool
	AuxData    InclusionAuxData
}

type MarketAuxDataFetch func(SingletonMarketSource) (SingletonMarketAuxData, error)

// VerifyActive is the primary entrypoint for the verification routine
// auxDataResolver is de-factor call to the Market actor to fetch the aux data
func (dap DataAggregationProof) VerifyActive(verifierData InclusionVerifierData, auxDataFetch MarketAuxDataFetch) error {
	if dap.AuxDataType != 0 {
		return xerrors.Errorf("invalid AuxDataType")
	}

	marketData, err := auxDataFetch(dap.AuxDataSource)
	if err != nil {
		return xerrors.Errorf("aux data could not be fetched: %w", err)
	}
	if !marketData.DealActive {
		return xerrors.Errorf("the deal is not active")
	}
	expectedAux, err := dap.ComputeExpectedAuxData(verifierData)
	if err != nil {
		return xerrors.Errorf("computing expected aux data failed: %w", err)
	}
	if *expectedAux != marketData.AuxData {
		return xerrors.Errorf("computed and market aux data don't match")
	}
	return nil
}

// ComputeExpectedAuxData exposes the raw AuxData computation from the proof for composability
func (dap DataAggregationProof) ComputeExpectedAuxData(verifierData InclusionVerifierData) (*InclusionAuxData, error) {
	return dap.Inclusion.ComputeExpectedAuxData(verifierData)
}
