package util

import (
	"errors"
	"math/bits"
)

// CheckedMultiply multiplies a and b and returns (truncate(a*b), no_overflow)
func CheckedMultiply(a, b uint64) (uint64, bool) {
	hi, lo := bits.Mul64(a, b)
	return lo, hi == 0
}

// Max returns the minimum value of inputs x, y
func Max(x int, y int) int {
	if x > y {
		return x
	}
	return y
}

// Min returns the minimum value of inputs x, y
func Min(x int, y int) int {
	if x < y {
		return x
	}
	return y
}

// Ceil computes the ceiling of x/y for x, y being integers
func Ceil(x uint, y uint) int {
	if x == 0 {
		return 0
	}
	return int(1 + ((x - 1) / y))
}

func IsPow2(value uint64) bool {
	if value == 0 {
		return true
	}
	return value&(value-1) == 0
}

// Log2Ceil computes the integer logarithm with ceiling for 64 bit unsigned ints
func Log2Ceil(value uint64) int {
	if value <= 1 {
		return 0
	}
	return Log2Floor(value-1) + 1
}

func Log2Floor(value uint64) int {
	if value == 0 {
		return 0
	}
	zeros := bits.LeadingZeros64(value)
	return 64 - zeros - 1
}

var ErrInputTooLarge = errors.New("input value too large")

func CeilPow2(value uint64) (uint64, error) {
	if value > 1<<63 {
		return 0, ErrInputTooLarge
	}
	if value == 0 {
		return 0, nil
	}
	return 1 << Log2Ceil(value), nil
}
