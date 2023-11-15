package main

import (
	"fmt"
	"gobpf/cebpf/tp"
)

func main() {
	fmt.Println("启动bpf")
	tp.LoadTp001()
}
