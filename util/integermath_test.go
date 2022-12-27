package util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLog2(t *testing.T) {
	assert.Equal(t, 0, Log2Ceil(1))
	assert.Equal(t, 2, Log2Ceil(4))
	assert.Equal(t, 3, Log2Ceil(7))
}
