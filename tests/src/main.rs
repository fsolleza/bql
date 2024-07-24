use bql_lib::codegen::{BinaryOperator, Expr, Kind};
use bql_lib::kernel_plan::{
	AppendKernelData, BpfContext, CurrentTaskField, SelectKernelData,
	KernelBpfMap, KernelPlan, PerfMapBufferAndOutput, SysEnterField, Timestamp,
};
use bql_lib::schema::{Schema, SchemaBuilder, SchemaKind};
use bql_lib::user_plan::{
	Filter, PrintData, ReadFromPerfEventArray, UserPlan, UserScalar,
};
use bql_lib::user_plan_helpers::*;

fn q1() {
	// Kernel space plan

	let plan_output_t = Kind::cstruct(&[
		("timestamp".into(), Kind::uint64_t()),
		("syscall_number".into(), Kind::uint64_t()),
		("pid".into(), Kind::uint64_t()),
	]);

	let mut kernel_ctx_builder =
		BpfContext::SyscallEnter.kernel_context_builder();

	let pid_schema = CurrentTaskField::Pid.as_kernel_schema();
	let syscall_num_schema = SysEnterField::SyscallNumber.as_kernel_schema();
	let timestamp_schema = Timestamp::new().as_kernel_schema();

	kernel_ctx_builder.add_kernel_variable(syscall_num_schema);
	kernel_ctx_builder.add_kernel_variable(timestamp_schema);
	kernel_ctx_builder.add_kernel_variable(pid_schema);

	let kernel_ctx = kernel_ctx_builder.build();

	let mut plan = KernelPlan::from_parts(kernel_ctx.clone(), &plan_output_t);

	// Maps
	let buffer = KernelBpfMap::per_cpu_buffer(256, &plan_output_t);
	let perf_array = KernelBpfMap::perf_event_array(&buffer.value_kind());

	// Ops
	let filter_op = SelectKernelData::new(
		pid_schema,
		BinaryOperator::Eq,
		Expr::uint(2414061),
		&kernel_ctx,
	)
	.into_op();

	//let filter_op = FilterKernelData::new(
	//	pid_schema,
	//	BinaryOperator::Eq,
	//	Expr::uint(pid),
	//	&kernel_ctx,
	//)
	//.into_op();

	let append_timestamp_op = AppendKernelData::new(
		&kernel_ctx,
		timestamp_schema,
		// TODO: We kind of hardcoded this access... need to clean up API
		plan.output_variable().lvalue().member("timestamp"),
	)
	.into_op();

	let append_syscall_number_op = AppendKernelData::new(
		&kernel_ctx,
		syscall_num_schema,
		// TODO: We kind of hardcoded this access... need to clean up API
		plan.output_variable().lvalue().member("syscall_number"),
	)
	.into_op();

	let append_pid = AppendKernelData::new(
		&kernel_ctx,
		pid_schema,
		// TODO: We kind of hardcoded this access... need to clean up API
		plan.output_variable().lvalue().member("pid"),
	)
	.into_op();

	let output_op = PerfMapBufferAndOutput::new(
		&kernel_ctx,
		&perf_array,
		&buffer,
		&plan.output_variable(),
	)
	.into_op();

	plan.add_map(&buffer);
	plan.add_map(&perf_array);

	plan.add_op(filter_op);
	plan.add_op(append_timestamp_op);
	plan.add_op(append_syscall_number_op);
	plan.add_op(append_pid);
	plan.add_op(output_op);

	let mut obj = plan.compile_and_load();

	// User space Plan
	let map = obj.map_mut(perf_array.name()).unwrap();
	let buffer_t = buffer.value_kind();
	let item_t = plan_output_t.clone();
	let schema = SchemaBuilder::new()
		.add_field("timestamp", SchemaKind::u64)
		.add_field("syscall_number", SchemaKind::u64)
		.add_field("pid", SchemaKind::u64)
		.build();

	// Userspace Operators
	let read_op =
		ReadFromPerfEventArray::new(map, &item_t, &buffer_t, &schema).to_op();

	let transform = TransformOp::Init("syscall_number".into());
	let compare = CompareOp::TransformEqScalar(transform, UserScalar::U64(1));
	let filter_op = Filter::new(compare, read_op).to_op();
	let print_op = PrintData::new(filter_op).to_op();

	let mut user_plan = UserPlan::new(obj, print_op);
	user_plan.execute();
}

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
	/// Target pid to capture data. Default = 0, captures all pids
	#[arg(short, long, default_value_t = 0)]
	pid: u64,

	/// Target syscall number to monitor. Default = 0, captures all syscalls
	#[arg(short, long, default_value_t = 0)]
	syscall_number: u64,
}

fn main() {
	q1();
}
