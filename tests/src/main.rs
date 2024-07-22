use bql_lib::codegen::*;
use bql_lib::kernel_plan::*;
use bql_lib::user_plan::*;
use bql_lib::schema::*;

fn main() {

	// Kernel space plan

	let plan_output_t = Kind::cstruct(
		&[
		("syscall_number".into(), Kind::uint64_t()),
		("pid".into(), Kind::uint64_t()),
		],
		);

	let mut kernel_ctx_builder =
		BpfContext::SyscallEnter.kernel_context_builder();

	kernel_ctx_builder
		.add_kernel_variable(SysEnterField::SyscallNumber.schema());
	kernel_ctx_builder
		.add_kernel_variable(CurrentTaskField::Pid.schema());

	let kernel_ctx = kernel_ctx_builder.build();

	let mut plan = KernelPlan::from_parts(kernel_ctx.clone(), &plan_output_t);

	// Maps
	let buffer = KernelBpfMap::per_cpu_buffer(256, &plan_output_t);
	let perf_array = KernelBpfMap::perf_event_array(&buffer.value_kind());

	// Ops
	let filter_op = FilterKernelData::new(
		CurrentTaskField::Pid.schema(),
		BinaryOperator::Eq,
		Expr::uint(0),
		&kernel_ctx
		).into_op();

	let append_syscall_number_op = AppendKernelData::new(
		&kernel_ctx,
		SysEnterField::SyscallNumber.schema(),
		plan.output_variable().lvalue().member("syscall_number"), // TODO: This seems to be hardcoded
		).into_op();

	let append_pid = AppendKernelData::new(
		&kernel_ctx,
		CurrentTaskField::Pid.schema(),
		plan.output_variable().lvalue().member("pid"), // TODO: This seems to be hardcoded
		).into_op();

	let output_op = PerfMapBufferAndOutput::new(
		&kernel_ctx,
		&perf_array,
		&buffer,
		&plan.output_variable()
		).into_op();

	plan.add_map(&buffer);
	plan.add_map(&perf_array);

	plan.add_op(filter_op);
	plan.add_op(append_syscall_number_op);
	plan.add_op(append_pid);
	plan.add_op(output_op);

	let mut obj = plan.compile_and_load();

	// User space Plan
	let map = obj.map_mut(perf_array.name()).unwrap();
	let buffer_t = buffer.value_kind();
	let item_t = plan_output_t.clone();
	let schema = SchemaBuilder::new()
		.add_field("syscall_number", SchemaKind::u64)
		.add_field("pid", SchemaKind::u64)
		.build();

	// Userspace Operators
	let read_op = ReadFromPerfEventArray::new(map, &item_t, &buffer_t, &schema).to_op();
	let print_op = PrintData::new(read_op).to_op();

	let mut user_plan = UserPlan::new(obj, print_op);
	user_plan.execute();
}
