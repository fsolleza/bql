#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile uint32_t TARGET_PID = 0;
const volatile uint32_t TARGET_SYSCALL_NUMBER = 0;

typedef struct {
	uint64_t pad;
	int64_t syscall_number;
	uint32_t args[6];
} ctx_t;

typedef struct event_t {
	uint32_t pid;
	uint64_t syscall_number;
	uint64_t start_time;
} event_t;

const event_t EVENT = {0};

typedef struct buffer_t {
	uint32_t length;
	event_t buffer[256];
} buffer_t;
const buffer_t BUFFER = {0};

typedef struct buffers_t {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, buffer_t);
	__uint(max_entries, 1);
} buffers_t;

buffers_t buffers SEC(".maps");

typedef struct perf_ring_t {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} perf_ring_t;

perf_ring_t perf_ring SEC(".maps");

static __always_inline
int filter_syscall(ctx_t *ctx, event_t *event) {
    int syscall_number = ctx->syscall_number;
	if ((TARGET_SYSCALL_NUMBER != 0) && (TARGET_SYSCALL_NUMBER != syscall_number)) {
		return 1;
	}
	return 0;
}

static __always_inline
int filter_pid(ctx_t *ctx, event_t *event) {

	int r = filter_syscall(ctx, event);
	if (r > 0) {
		return r;
	}

    struct task_struct* task;
	task = (struct task_struct *)bpf_get_current_task();

    uint32_t pid = 0;
    bpf_probe_read(&pid, sizeof(pid), &task->tgid);
	if ((TARGET_PID != 0) && (TARGET_PID != pid)) {
		return 1;
	}
	return 0;
}

static __always_inline
int append_timestamp(ctx_t *ctx, event_t *event) {
	int r = filter_pid(ctx, event);
	if (r > 0) {
		return r;
	}

	event->start_time = bpf_ktime_get_ns();
	return 0;
}

static __always_inline
int append_pid(ctx_t *ctx, event_t *event) {
	int r = append_timestamp(ctx, event);
	if (r > 0) {
		return r;
	}

    struct task_struct* task;
	task = (struct task_struct *)bpf_get_current_task();
    uint32_t pid = 0;
    bpf_probe_read(&pid, sizeof(pid), &task->tgid);
	event->pid = pid;
	return 0;
}

static __always_inline
int append_syscall(ctx_t *ctx, event_t *event) {
	int r = append_pid(ctx, event);
	if (r > 0) {
		return r;
	}

    int syscall_number = ctx->syscall_number;
	event->syscall_number = syscall_number;
	return 0;
}

static __always_inline
int buffer_and_output(ctx_t *ctx, event_t *event) {
	int r = append_syscall(ctx, event);
	if (r > 0) {
		return r;
	}

	int zero = 0;
    buffer_t *b = bpf_map_lookup_elem(&buffers, &zero);
    if (!b) {
    	bpf_printk("ERROR GETTING BUFFER");
    	return 1;
	}

    if (b->length < 256) {
		b->buffer[b->length] = *event;
    	b->length += 1;
	}

	if (b->length == 256) {
    	bpf_perf_event_output(
			(void *)ctx,
			&perf_ring,
			BPF_F_CURRENT_CPU,
			b,
			sizeof(*b)
		);
    	b->length = 0;
	}
	return 0;
}

static __always_inline
int root_operator(ctx_t *ctx, event_t *event) {
	buffer_and_output(ctx, event);
}

static __always_inline
int handle_sys_enter(ctx_t *ctx) {
	if (!ctx)
		return 1;
    struct task_struct* task;
	task = (struct task_struct *)bpf_get_current_task();
    uint32_t pid = 0;
    bpf_probe_read(&pid, sizeof(pid), &task->tgid);
    int zero = 0;
    uint64_t time = bpf_ktime_get_ns();
    int syscall_number = ctx->syscall_number;

	if ((TARGET_PID != 0) && (TARGET_PID != pid)) {
		return 1;
	}

	if ((TARGET_SYSCALL_NUMBER != 0) && (TARGET_SYSCALL_NUMBER != syscall_number)) {
		return 1;
	}

    event_t e = {0};
    e.pid = pid;
    e.syscall_number = syscall_number;
    e.start_time = time;
	
    buffer_t *b = bpf_map_lookup_elem(&buffers, &zero);
    if (!b) {
    	bpf_printk("ERROR GETTING BUFFER");
    	return 1;
	}

    if (b->length < 256) {
		b->buffer[b->length] = e;
    	b->length += 1;
	}

	if (b->length == 256) {
    	bpf_perf_event_output(
			(void *)ctx,
			&perf_ring,
			BPF_F_CURRENT_CPU,
			b,
			sizeof(*b)
		);
    	b->length = 0;
	}
	return 0;
}

SEC("tp/raw_syscalls/sys_enter")
int probe_sys_enter(ctx_t *ctx) {
	return handle_sys_enter(ctx);


	//event_t e = {0};
	//return root_operator(ctx, &e);
}

