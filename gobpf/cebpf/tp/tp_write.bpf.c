//go:build ignore
#include <common.h>
#include <linux/limits.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
typedef unsigned int u32;

struct data_t {
    u32 pid;
    char comm[256];  // NAME MAX 文件名的最大长度，通常也可以用于进程或线程名称的最大长度
};

// struct bpf_map_def SEC("maps") log_map = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,  // 类型
//     .key_size = sizeof(u32),
//     .value_size = sizeof(__u32),
//     .max_entries = 0,  // 用户态不需要向他发送数据 可以为0
// };

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} log_map SEC(".maps");

// 函数名随意取
SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(void* ctx) {
    struct data_t* data;
    data = bpf_ringbuf_reserve(&log_map, sizeof(*data), 0);
    if (!data) {
        return 0;
    }
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    // 提交数据到 ring buffer
    bpf_ringbuf_submit(data, 0);
    return 0;
}
