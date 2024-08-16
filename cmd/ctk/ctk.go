package main

import (
	"fmt"

	"github.com/pmuens/ctk-go/ctk"
)

func main() {
	result := ctk.Mul(42, 2)
	fmt.Printf("42 * 2 = %v\n", result)
}
