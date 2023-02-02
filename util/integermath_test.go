package util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLog2(t *testing.T) {
	assert.Equal(t, 0, Log2Ceil(0))
	assert.Equal(t, 0, Log2Ceil(1))
	assert.Equal(t, 1, Log2Ceil(2))
	assert.Equal(t, 2, Log2Ceil(4))
	assert.Equal(t, 3, Log2Ceil(7))
	assert.Equal(t, 4, Log2Ceil(9))
	assert.Equal(t, 64, Log2Ceil(18446744073709551614))
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
