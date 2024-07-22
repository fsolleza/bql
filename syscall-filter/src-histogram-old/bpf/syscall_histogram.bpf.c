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

// PERF_EVENT_ARRAY to communicate with userspace
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} perf_buffer SEC(".maps");

//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__type(key, __u32);
//	__type(value, __u64);
//	//__uint(max_entries, 100);
//	__uint(max_entries, 256);
//} tid_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct syscall_event_buffer);
	__uint(max_entries, 1);
} syscall_buffers SEC(".maps");

struct {
	--uint(type, BPF_MAP_TYPE_HASH);
	--type(key, int);
	--type(value, int);
	--uint(max_entries, 32);
} syscall_map SEC("maps"); 

//SEC("tp/raw_syscalls/sys_exit")
//int handle_sys_exit(struct sys_exit_ctx *ctx) {
//	struct task_struct* task = (struct task_struct*)bpf_get_current_task();
//	uint32_t pid = 0;
//	uint32_t tid = 0;
//	bpf_probe_read(&pid, sizeof(pid), &task->tgid);
//	bpf_probe_read(&tid, sizeof(pid), &task->pid);
//	int zero = 0;
//	if ((target_pid == 0) || (pid == target_pid)) {
//	//if (target_pid == 0) || (pid == target_pid) {
//	//if (pid == target_pid && ctx->syscall_number != 202) {
//		uint64_t time = bpf_ktime_get_ns();
//		uint64_t * start = bpf_map_lookup_elem(&tid_start, &tid);
//		if (!start) {
//			bpf_printk("ERROR GETTING START TIME");
//			return 0;
//		}
//		int syscall_number = ctx->syscall_number;
//		struct syscall_event e = {0};
//		e.pid = pid;
//		e.tid = tid;
//		e.duration = time - *start;
//		e.syscall_number = syscall_number;
//		e.start_time = *start;
//
//		//bpf_perf_event_output((void *)ctx, &perf_buffer, BPF_F_CURRENT_CPU, (void*)&e, sizeof(e));
//
//		struct syscall_event_buffer *buffer = bpf_map_lookup_elem(&syscall_buffers, &zero);
//		if (!buffer) {
//			bpf_printk("ERROR GETTING BUFFER");
//			return 0;
//		}
//
//		if (buffer->length < 256) {
//			buffer->buffer[buffer->length] = e;
//			buffer->length += 1;
//		}
//
//		if (buffer->length == 256) {
//			bpf_perf_event_output((void *)ctx, &perf_buffer, BPF_F_CURRENT_CPU, buffer, sizeof(*buffer));
//			buffer->length = 0;
//		}
//
//	}
//	return 0;
//}

//SEC("tp/raw_syscalls/sys_enter")
//int handle_sys_enter(struct sys_enter_ctx *ctx) {
//	struct task_struct* task = (struct task_struct*)bpf_get_current_task();
//	uint32_t pid = 0;
//	uint32_t tid = 0;
//	bpf_probe_read(&pid, sizeof(pid), &task->tgid);
//	bpf_probe_read(&tid, sizeof(pid), &task->pid);
//	int zero = 0;
//	if ((target_pid == 0) || (pid == target_pid)) {
//	//if ((pid == target_pid) && (ctx->syscall_number != 202)) {
//		uint64_t time = bpf_ktime_get_ns();
//		if (bpf_map_update_elem(&tid_start, &tid, &time, BPF_ANY) != 0) {
//			bpf_printk("ERROR UPDATING START TIME");
//		}
//	}
//	return 0;
//}

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

    int value = bpf_map_lookup_elem(&syscall_map, &syscall_number);
    if (!value) {
	int one = 1;
	bpf_map_update_elem(&syscall_map, &syscall_number, &one);
    } else {
	bpf_map_update_elem(&syscall_map, &syscall_number, &(value + 1)); 
    }

    struct syscall_event_buffer *buffer = bpf_map_lookup_elem(&syscall_buffers, &zero);
    if (!buffer) {
        bpf_printk("ERROR GETTING BUFFER");
        return 0;
    }

    if (buffer->length < 256) {
       	buffer->buffer[buffer->length] = e;
        buffer->length += 1;
    }

    if (buffer->length == 256) {
        bpf_perf_event_output((void *)ctx, &perf_buffer, BPF_F_CURRENT_CPU, buffer, sizeof(*buffer));
        buffer->length = 0;
    }

    return 0;
}
