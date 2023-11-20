package main

import (
	"fmt"
	"gobpf/cebpf/docker"
)

func main() {
	fmt.Println("run")
	docker.LoadDockerXdp()
}
