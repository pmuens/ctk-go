package ctk

func Mul(a, b int) int {
	result := 0

	for range a {
		result = add(result, b)
	}

	return result
}

func add(a, b int) int {
	return a + b
}
