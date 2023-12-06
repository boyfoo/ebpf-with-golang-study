package main

import (
	"gobpf/cebpf/gotools"
)

func main() {
	gotools.LoadGoTool("/root/mytest/gobpf/httpapp")
}
