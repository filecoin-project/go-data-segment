package main

import (
	"github.com/filecoin-project/go-data-segment/datasegment"
	"github.com/filecoin-project/go-data-segment/merkletree"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteTupleEncodersToFile("../merkletree/cbor_gen.go", "merkletree",
		merkletree.ProofDataSerialization{},
	); err != nil {
		panic(err)
	}
	if err := cbg.WriteTupleEncodersToFile("../datasegment/cbor_gen.go", "datasegment",
		datasegment.InclusionProof{},
		datasegment.InclusionAuxData{},
		datasegment.InclusionVerifierData{},
		datasegment.DataAggregationProof{},
	); err != nil {
		panic(err)
	}
}
