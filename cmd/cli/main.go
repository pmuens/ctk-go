package main

import (
	"fmt"

	"github.com/pmuens/xchacha20-poly1305/internal"
)

func main() {
	result := internal.Mul(42, 2)
	fmt.Printf("42 * 2 = %v\n", result)
}
