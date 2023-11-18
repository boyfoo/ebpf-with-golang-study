package main

import (
	"fmt"
	"gobpf/cebpf/sys"
)

func main() {
	fmt.Println("run")
	// sys.LoadSys()
	// sys.LoadSwich()
	sys.LoadBash()
}
