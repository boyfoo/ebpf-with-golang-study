package gotools

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 gotool gotool.bpf.c -- -I $BPF_HEADERS
