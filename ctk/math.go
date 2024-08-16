package ctk

// Mul multiplies a by b and returns the result.
func Mul(a, b int) int {
	result := 0

	for range a {
		result = add(result, b)
	}

	return result
}

// add adds a and b and returns the result.
func add(a, b int) int {
	return a + b
}
