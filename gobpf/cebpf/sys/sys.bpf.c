//go:build ignore
//     #include <common.h>
#include <vmlinux.h>

#include <bpf_helpers.h>
#include <bpf_tracing.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct proc_t {
    __u32 pid;
    __u32 ppid;  // 父进程id
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
    struct proc_t* p = NULL;
    p = bpf_ringbuf_reserve(&proc_map, sizeof(*p), 0);
    if (!p) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    p->pid = pid;
    p->ppid = 0;

    // 当前执行进程的对应的task_struct指针
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        //     // 读取到父进程task_struct
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&p->ppid, sizeof(p->ppid), &parent->pid);
        }
    }
    bpf_get_current_comm(&p->pname, sizeof(p->pname));
    bpf_ringbuf_submit(p, 0);
    return 0;
}
