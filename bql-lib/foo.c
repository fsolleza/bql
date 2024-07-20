#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
typedef uint32_t ArrKind_1[6];
typedef struct {
	uint64_t pad;
	int64_t syscall_number;
	ArrKind_1 args;
} struct_2;
typedef struct {
	uint64_t syscall_number;
	uint64_t start_time;
} struct_0;
typedef struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct_4);
	__max_entries(max_entries, 1);
} per_cpu_array_t_5;
per_cpu_array_t_5 var_4
SEC(".maps");
typedef struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} perf_event_array_t_6;
perf_event_array_t_6 var_5
SEC(".maps");
SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct_2 *var_0)
{
	int var_1;
	var_1 = var_0->syscall_number;
	int var_2;
	bpf_get_current_task(&(var_2), sizeof(var_2), &(bpf_get_current_task()->pid));
	struct_0 var_3;
	var_3 = {0};

	if ((var_2) != (17)) {
		return 0;
	}

	var_3.syscall_number = var_1;
	int var_6;
	var_6 = 0;
	struct_4 *var_7;
	var_7 = bpf_map_lookup_elem(&(var_4), &(var_6));

	if (!(var_7)) {
		return 0;
	}

	if ((var_7->length) < (256)) {
		var_7->buffer[1] = var_3;
		var_7->length += 1;
	}

	if ((var_7->length) == (256)) {
		bpf_perf_event_output((void *)var_0, &(var_5), BPF_F_CURRENT_CPU, var_7,
		    sizeof(*var_7));
		var_7->length = 0;
	}

	return 0;
}
