// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
//#include <linux/sched.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile uint32_t my_pid = 0;
const volatile uint32_t target_pid = 0;

// from: /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format
struct sys_enter_ctx {
	uint64_t pad;
	int64_t syscall_number;
	uint32_t args[6];
};

struct sys_exit_ctx {
	uint64_t pad;
	int64_t syscall_number;
	uint64_t ret;
};

struct syscall_event {
	uint32_t pid;
	uint32_t tid;
	uint64_t syscall_number;
	uint64_t start_time;
	uint64_t duration;
};

struct syscall_event_buffer {
	uint32_t length;
	struct syscall_event buffer[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct syscall_event_buffer);
	__uint(max_entries, 1);
} syscall_buffers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 32);
} syscall_map SEC(".maps"); 

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_ctx *ctx) {
	struct task_struct* task = (struct task_struct*)bpf_get_current_task();
	uint32_t pid = 0;
	uint32_t tid = 0;
	bpf_probe_read(&pid, sizeof(pid), &task->tgid);
	bpf_probe_read(&tid, sizeof(pid), &task->pid);
	int zero = 0;
	uint64_t time = bpf_ktime_get_ns();
	int syscall_number = ctx->syscall_number;

	struct syscall_event e = {0};
	e.pid = pid;
	e.tid = tid;
	e.duration = 0 ;
	e.syscall_number = syscall_number;
	e.start_time = time;	

	int* value = bpf_map_lookup_elem(&syscall_map, &syscall_number);
	int updated_val = 1;
	if (value) {
		updated_val += *value;
		int one = 1;
	}
	bpf_map_update_elem(&syscall_map, &syscall_number, &updated_val, BPF_ANY);

	return 0;
}
