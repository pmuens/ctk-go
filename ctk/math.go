package ctk

const (
	// ErrDivisionByZero is returned if there's an attempt to divide by zero.
	ErrDivisionByZero = Error("division by zero")
)

// Mul multiplies a by b and returns the result.
func Mul(a, b int) int {
	result := 0

	for range a {
		result = add(result, b)
	}

	return result
}

// Div divides a by b and returns the rounded-down result.
// Returns an error if b is zero (division by zero).
func Div(a, b int) (int, error) {
	if b == 0 {
		return 0, ErrDivisionByZero
	}

	return a / b, nil
}

// add adds a and b and returns the result.
func add(a, b int) int {
	return a + b
}
