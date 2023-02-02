package util

import "math/bits"

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

// Log2Ceil computes the integer logarithm with ceiling for 64 bit unsigned ints
func Log2Ceil(value uint64) int {
	zeros := bits.LeadingZeros64(value)
	ones := bits.OnesCount64(value)
	inc := 0
	// If the number is not a two power, then we need to increment to get the ceiling
	if ones > 1 {
		inc = 1
	}
	// Max ensure the edge case of value = 0 is correctly handled
	return Max(0, 64-zeros-1+inc)
}
