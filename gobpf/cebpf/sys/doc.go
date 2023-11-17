package sys

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS sys sys.bpf.c -- -I $BPF_HEADERS
