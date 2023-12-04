package main

import "gobpf/cebpf/arp"

func main() {
	arp.LoadArp()
	// arp.GoReply()
}
