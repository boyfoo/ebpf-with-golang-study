package dockertc

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 dockertc dockertc.bpf.c -- -I $BPF_HEADERS
