package merkletree

import (
	"fmt"
	"io"

	cbg "github.com/whyrusleeping/cbor-gen"
	xerrors "golang.org/x/xerrors"
)

// ProofData should encode as [uint64, [[path_element1],[path_element2],[path_element3]]
// but cbor-gen refuses to encode constant sized byte arrays, so we have to increase complexity

func (pd *ProofData) MarshalCBOR(w io.Writer) error {
	var pds *ProofDataSerialization
	if pd != nil {
		pds = &ProofDataSerialization{Index: pd.index, Path: nodeArray{nodes: pd.path}}
	}

	return pds.MarshalCBOR(w)

}

func (nd *ProofData) UnmarshalCBOR(r io.Reader) error {
	var pds ProofDataSerialization
	err := pds.UnmarshalCBOR(r)
	if err != nil {
		return err
	}

	nd.index = pds.Index
	nd.path = pds.Path.nodes
	return nil
}

type ProofDataSerialization struct {
	Index uint64
	Path  nodeArray
}

const maxPathLength = 128

// encodes as transparent array
type nodeArray struct {
	nodes []Node
}

var _ cbg.CBORUnmarshaler = (*nodeArray)(nil)
var _ cbg.CBORMarshaler = (*nodeArray)(nil)

func (nd *nodeArray) UnmarshalCBOR(r io.Reader) error {
	*nd = nodeArray{}

	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajArray {
		return fmt.Errorf("expected cbor array")
	}

	if extra > maxPathLength {
		return fmt.Errorf("inclusion proof longer than expected")
	}

	if extra > 0 {
		nd.nodes = make([]Node, extra)
	}

	for i := 0; i < int(extra); i++ {
		if err := nd.nodes[i].UnmarshalCBOR(cr); err != nil {
			return err
		}
	}

	return nil
}

func (nd *nodeArray) MarshalCBOR(w io.Writer) error {
	if nd == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if len(nd.nodes) > maxPathLength {
		return fmt.Errorf("inclusion proof longer than expected")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajArray, uint64(len(nd.nodes))); err != nil {
		return err
	}
	for _, v := range nd.nodes {
		if err := v.MarshalCBOR(cw); err != nil {
			return err
		}
	}

	return nil
}

var _ cbg.CBORUnmarshaler = (*Node)(nil)
var _ cbg.CBORMarshaler = (*Node)(nil)

func (n *Node) UnmarshalCBOR(r io.Reader) error {
	*n = Node{}

	nb, err := cbg.ReadByteArray(r, digestBytes)

	if err != nil {
		return xerrors.Errorf("reading cbor bytearray: %w", err)
	}
	if len(nb) != digestBytes {
		return xerrors.Errorf("to few bytes for full node: %d", len(n))
	}

	copy(n[:], nb)
	return nil
}

func (n *Node) MarshalCBOR(w io.Writer) error {
	if n == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	return cbg.WriteByteArray(w, n[:])
}
