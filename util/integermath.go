package util

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
func Ceil(x int, y int) int {
	if x == 0 {
		return 0
	}
	return 1 + ((Abs(x) - 1) / Abs(y))
}

func Abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Log2Ceil computes the integer logarithm with ceiling for up to 64 bit ints
// Translated from https://www.appsloveworld.com/c/100/6/compute-fast-log-base-2-ceiling
func Log2Ceil(value int) int {
	var y int
	if (value & (value - 1)) == 0 {
		y = 0
	} else {
		y = 1
	}
	j := 32
	for i := 0; i < 6; i++ {
		var k int
		if (uint64(value) & tab64[i]) == 0 {
			k = 0
		} else {
			k = j
		}
		y += k
		value >>= k
		j >>= 1
	}

	return y
}

var tab64 = [6]uint64{
	0xFFFFFFFF00000000,
	0x00000000FFFF0000,
	0x000000000000FF00,
	0x00000000000000F0,
	0x000000000000000C,
	0x0000000000000002}
