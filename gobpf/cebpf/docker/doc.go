package docker

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 dockerxdp docker.bpf.c -- -I $BPF_HEADERS
