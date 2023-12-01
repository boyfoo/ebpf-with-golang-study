package arp

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 myarp arp.bpf.c -- -I $BPF_HEADERS
