//go:build ignore
#include <common.h>
#include <linux/limits.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
typedef unsigned int u32;

struct data_t {
    u32 pid;
    char comm[256];  // NAME MAX 文件名的最大长度，通常也可以用于进程或线程名称的最大长度
};

struct bpf_map_def SEC("maps") log_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,  // 类型
    .key_size = sizeof(u32),
    .value_size = sizeof(__u32),
    .max_entries = 0,  // 用户态不需要向他发送数据 可以为0
};

int is_eq(char* str1, char* str2) {
    int eq = 1;
    int i;
    for (i = 0; i < sizeof(str1) - 1 && i < sizeof(str2) - 1; i++) {
        if (str1[i] != str2[i]) {
            eq = 0;
            break;
        }
    }
    return eq;
}

// 函数名随意取
SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(void* ctx) {
    char app_name[] = "testwrite";
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    int eq = is_eq(data.comm, app_name);
    if (eq == 1) {
        // 向用户态发送数据
        bpf_perf_event_output(ctx, &log_map, 0, &data.comm, sizeof(data.comm));
        // bpf_printk("pid=%d, name:%s \n", data.pid, data.comm);
    }
    return 0;
}
