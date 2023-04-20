package merkletree

import (
	"io"

	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	xerrors "golang.org/x/xerrors"
)

func (h *Hybrid) UnmarshalCBOR(r io.Reader) error {

	return nil
}
func (h *Hybrid) MarshalCBOR(w io.Writer) error {
	if h == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)
	if err := cw.WriteMajorTypeHeader(cbg.MajArray, uint64(2)); err != nil {
		return err
	}

	if h.log2Leafs < 0 {
		return xerrors.Errorf("log2Levels cannot be negative")
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(h.log2Leafs)); err != nil {
		return err
	}

	// early exit if subs is nil
	if h.data.subs == nil {
		_, err := cw.Write(cbg.CborNull)
		return err
	}

	indexes := maps.Keys(h.data.subs)
	slices.Sort(indexes)

	writeSub := func(idx uint64, sub []Node) error {
		if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(idx)); err != nil {
			return err
		}
		if err := cw.WriteMajorTypeHeader(cbg.MajArray, uint64(len(sub))); err != nil {
			return err
		}
		for _, s := range sub {
			var err error

			if s == (Node{}) {
				_, err = cw.Write(cbg.CborNull)
			} else {
				err = cbg.WriteByteArray(cw, s[:])
			}

			if err != nil {
				return err
			}
		}

		return nil
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajMap, uint64(len(indexes))); err != nil {
		return err
	}

	for _, idx := range indexes {
		if err := writeSub(idx, h.data.subs[idx]); err != nil {
			return xerrors.Errorf("writing sub: %w", err)
		}
	}

	return nil
}
