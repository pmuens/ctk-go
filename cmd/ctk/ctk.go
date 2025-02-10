package main

import (
	"fmt"

	"github.com/pmuens/xchacha20-poly1305/ctk"
)

func main() {
	result := ctk.Mul(42, 2)
	fmt.Printf("42 * 2 = %v\n", result)
}
