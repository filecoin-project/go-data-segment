package merkletree

import (
	"fmt"
	"io"
	"math"

	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	xerrors "golang.org/x/xerrors"
)

func (h *Hybrid) UnmarshalCBOR(r io.Reader) (err error) {

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
		return fmt.Errorf("cbor input should be of type array")
	}

	if extra != 2 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	{
		maj, extra, err = cr.ReadHeader()
		if err != nil {
			return err
		}
		if maj != cbg.MajUnsignedInt {
			return fmt.Errorf("wrong type for int field")
		}

		if extra > math.MaxInt {
			return xerrors.Errorf("log2Leafs in cbor too large")
		}

		newh, err := NewHybrid(int(extra))
		if err != nil {
			return xerrors.Errorf("creating new empty hybrid failed: %w", err)
		}
		*h = newh
	}

	{
		maj, extra, err := cr.ReadHeader()
		if err != nil {
			return err
		}
		if maj != cbg.MajMap {
			return fmt.Errorf("wrong type for map field")
		}
		mapItems := extra
		if mapItems == 0 {
			return nil
		}
		if mapItems*SparseBlockSize*NodeSize > 16<<30 {
			return xerrors.Errorf("too large map")
		}

		h.data.initSubs()
		for i := uint64(0); i < mapItems; i++ {
			maj, extra, err := cr.ReadHeader()
			if err != nil {
				return err
			}
			if maj != cbg.MajUnsignedInt {
				return fmt.Errorf("wrong type for uint field")
			}

			index := extra

			maj, extra, err = cr.ReadHeader()
			if err != nil {
				return err
			}

			if maj != cbg.MajArray {
				return fmt.Errorf("wrong type for int field")
			}
			if extra != SparseBlockSize {
				return fmt.Errorf("incompatible sparse block size")
			}
			sparseBlock := make([]Node, SparseBlockSize)

			for j := 0; j < SparseBlockSize; j++ {
				b, err := cr.ReadByte()
				if err != nil {
					return err
				}
				if b == cbg.CborNull[0] {
					continue
				}
				if err := cr.UnreadByte(); err != nil {
					return err
				}
				maj, extra, err := cr.ReadHeader()
				if err != nil {
					return err
				}
				if maj != cbg.MajByteString {
					return xerrors.Errorf("wrong type for Node")
				}
				if extra != NodeSize {
					return xerrors.Errorf("wrong size for Node")
				}
				io.ReadFull(cr, sparseBlock[j][:])
			}
			h.data.subs[index] = sparseBlock

		}

	}

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

	if len(h.data.subs)*SparseBlockSize*NodeSize > 16<<30 {
		return xerrors.Errorf("too large map")
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
