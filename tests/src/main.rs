use bql_lib::codegen::*;
use bql_lib::physical_plan::*;
use bql_lib::executor::*;

fn main() {
	bump_memlock_rlimit();

	let plan_output_t = Kind::cstruct(
		&[
		("syscall_number".into(), Kind::uint64_t()),
		("start_time".into(), Kind::uint64_t()),
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
		BinaryOperator::Neq,
		Expr::uint(17),
		&kernel_ctx
		).into_op();

	let append_syscall_number_op = AppendKernelData::new(
		&kernel_ctx,
		SysEnterField::SyscallNumber.schema(),
		plan.output_variable().lvalue().member("syscall_number"), // TODO: This seems to be hardcoded
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
	plan.add_op(output_op);

	let obj = plan.generate_code().compile_and_load();
}
