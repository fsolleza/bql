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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1024);
} syscall_map SEC(".maps"); 

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_ctx *ctx) {
	struct task_struct* task = (struct task_struct*)bpf_get_current_task();
	int syscall_number = ctx->syscall_number;

	int* value = bpf_map_lookup_elem(&syscall_map, &syscall_number);
	if (!value) {
		int one = 1;
		bpf_map_update_elem(&syscall_map, &syscall_number, &one, BPF_ANY);
	} else {
		*value += 1;
	}

	return 0;
}
