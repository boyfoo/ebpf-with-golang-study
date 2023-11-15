//go:build ignore
#include <common.h>
#include <linux/limits.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
typedef unsigned int u32;

struct data_t
{
    u32 pid;
    char comm[256]; // NAME MAX 文件名的最大长度，通常也可以用于进程或线程名称的最大长度
};

int is_eq(char *str1, char *str2)
{
    int eq = 1;
    int i;
    for (i = 0; i < sizeof(str1) - 1 && i < sizeof(str2) - 1; i++)
    {
        if (str1[i] != str2[i])
        {
            eq = 0;
            break;
        }
    }
    return eq;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    char app_name[] = "testwrite";
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    int eq = is_eq(data.comm, app_name);
    if (eq == 1)
    {
        bpf_printk("pid=%d, name:%s \n", data.pid, data.comm);
    }
    return 0;
}
