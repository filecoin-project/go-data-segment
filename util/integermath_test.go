package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLog2Ceil(t *testing.T) {
	assert.Equal(t, 0, Log2Ceil(0))
	assert.Equal(t, 0, Log2Ceil(1))
	assert.Equal(t, 1, Log2Ceil(2))
	assert.Equal(t, 2, Log2Ceil(4))
	assert.Equal(t, 3, Log2Ceil(7))
	assert.Equal(t, 4, Log2Ceil(9))
	assert.Equal(t, 64, Log2Ceil(18446744073709551614))
}
func TestLog2Floor(t *testing.T) {
	assert.Equal(t, 0, Log2Floor(0))
	assert.Equal(t, 0, Log2Floor(1))
	assert.Equal(t, 1, Log2Floor(2))
	assert.Equal(t, 2, Log2Floor(4))
	assert.Equal(t, 2, Log2Floor(7))
	assert.Equal(t, 3, Log2Floor(8))
	assert.Equal(t, 3, Log2Floor(9))
	assert.Equal(t, 62, Log2Floor(1<<63-1))
	assert.Equal(t, 63, Log2Floor(1<<64-1))
}

func TestCeilPow2(t *testing.T) {
	tt := []struct {
		input  uint64
		output uint64
		err    error
	}{
		{0, 0, nil}, {1, 1, nil}, {2, 2, nil}, {3, 4, nil}, {13, 16, nil},
		{1324, 2048, nil}, {1<<62 + 1, 1 << 63, nil},
		{1<<63 - 1, 1 << 63, nil}, {1 << 63, 1 << 63, nil},
		{1<<63 + 1, 0, ErrInputTooLarge}, {1<<64 - 5, 0, ErrInputTooLarge},
		{1<<64 - 1, 0, ErrInputTooLarge},
	}

	for i, tc := range tt {
		out, err := CeilPow2(tc.input)
		assert.Equal(t, tc.output, out, "output not equal for input: %d (testcase %d)", tc.input, i)
		if tc.err == nil {
			assert.NoError(t, err, "for input: %d (testcase %d)", tc.input, i)
		} else {
			assert.Error(t, err, "error expected for input: %d (testcase %d)", tc.input, i)
			assert.ErrorIs(t, err, tc.err, "error not equal for input: %d (testcase %d)", tc.input, i)
		}
	}
}

func TestMax(t *testing.T) {
	assert.Equal(t, 0, Max(0, -1))
	assert.Equal(t, 123, Max(122, 123))
}

func TestMin(t *testing.T) {
	assert.Equal(t, -1, Min(0, -1))
	assert.Equal(t, 122, Min(122, 123))
}

func TestCeil(t *testing.T) {
	assert.Equal(t, 0, Ceil(0, 10))
	assert.Equal(t, 1, Ceil(10, 10))
	assert.Equal(t, 1, Ceil(10, 11))
	assert.Equal(t, 2, Ceil(10, 9))
}

func TestAbs(t *testing.T) {
	assert.Equal(t, 0, Max(0, -1))
	assert.Equal(t, 123, Max(122, 123))
}
