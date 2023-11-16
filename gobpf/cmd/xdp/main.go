package main

import (
	"fmt"
	"gobpf/cebpf/xdp"
)

func main() {
	fmt.Println("run")
	xdp.LoadXDP()
}
