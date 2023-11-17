//go:build ignore
#include <common.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
typedef unsigned int u32;

struct proc_t {
    u32 pid;
    char pname[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} proc_map SEC(".maps");

// 执行新程序的结束时候调用
// sys_enter_execve这个是前调用 会造成运行的程序都是由bash运行 所以程序名都是bash
SEC("tracepoint/syscalls/sys_exit_execve")
int handle(void* ctx) {
    struct proc_t* p;
    p = bpf_ringbuf_reserve(&proc_map, sizeof(*p), 0);
    if (!p) {
        return 0;
    }

    p->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&p->pname, sizeof(p->pname));

    bpf_ringbuf_submit(p, 0);
    return 0;
}
