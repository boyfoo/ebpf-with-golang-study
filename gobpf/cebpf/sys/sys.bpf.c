//go:build ignore
//             #include <common.h>
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
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (task) {
        struct task_struct* parent = NULL;
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

// 内核进程切换运行的时候触发
SEC("kprobe/finish_task_switch")
int finish_task_switch(struct task_struct* pre) {
    __u32 cur_pid = 0;
    // 上个进程
    __u32 pre_pid = 0;
    // 当前进程
    struct task_struct* cur = (struct task_struct*)bpf_get_current_task();
    if (cur) {
        bpf_probe_read_kernel(&cur_pid, sizeof(cur_pid), &(cur->pid));
    }
    if (pre) {
        bpf_probe_read_kernel(&pre_pid, sizeof(pre_pid), &(pre->pid));
    }
    if (pre_pid != 0) {
        bpf_printk("cur_pid=%u pre_pid=%u \n", cur_pid, pre_pid);
    }
    return 0;
}

struct base_event {
    u32 pid;
    u8 line[80];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} event_map SEC(".maps");

SEC("uretprobe/bash_readline")
int bash_readline(struct pt_regs* ctx) {
    struct base_event* event = NULL;
    event = bpf_ringbuf_reserve(&event_map, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    event->pid = bpf_get_current_pid_tgid() >> 32;
    // PT_REGS_RC 获取函数的返回值
    // 从用户态读用户数据 所以不用 bpf_probe_read_kernel
    bpf_probe_read(&event->line, sizeof(event->line), (void*)PT_REGS_RC(ctx));
    bpf_ringbuf_submit(event, 0);
    return 0;
}