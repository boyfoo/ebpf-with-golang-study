package tp

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS tp_write tp_write.bpf.c -- -I $BPF_HEADERS
