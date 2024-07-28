use bql_lib::codegen::{BinaryOperator, Expr, Kind};
use bql_lib::kernel_plan::{
	AsKernelVariableSource, BpfContext, CurrentTaskField, KernelBpfMap,
	KernelContextBuilder, KernelPlan, KernelVariable, PerfMapBufferAndOutput,
	SelectKernelData, SysEnterField, Timestamp, TupleBuilder,
};
use bql_lib::schema::{Schema, SchemaBuilder, SchemaKind};
use bql_lib::user_plan::{
	PrintData, ReadFromPerfEventArray, Select, SinkData, UserPlan, UserScalar,
};
use bql_lib::user_plan_helpers::*;

use std::{
	sync::atomic::{AtomicUsize, Ordering::SeqCst},
	thread,
	time::Duration,
};

static COUNT: AtomicUsize = AtomicUsize::new(0);
static LOST: AtomicUsize = AtomicUsize::new(0);

fn counter() {
	loop {
		let c = COUNT.swap(0, SeqCst);
		let l = LOST.swap(0, SeqCst);
		println!("Count: {} Lost: {}", c, l);
		thread::sleep(Duration::from_secs(1));
	}
}

fn lost_event_handler(_: i32, count: u64) {
	LOST.fetch_add(count as usize, SeqCst);
}

fn q1(pid: u64, syscall_num: u64) {
	let mut builder = KernelContextBuilder::new_syscall_enter_ctx();
	let ctx_var = builder.ctx_variable();

	let system_call = KernelVariable::new(
		&Kind::uint64_t(),
		&SysEnterField::SyscallNumber
			.as_kernel_schema()
			.as_kernel_variable_source(&ctx_var),
	);

	let process_pid = KernelVariable::new(
		&Kind::uint64_t(),
		&CurrentTaskField::Pid
			.as_kernel_schema()
			.as_kernel_variable_source(&ctx_var),
	);

	let timestamp = KernelVariable::new(
		&Kind::uint64_t(),
		&Timestamp::new()
			.as_kernel_schema()
			.as_kernel_variable_source(&ctx_var),
	);

	builder.add_kernel_variable(system_call.clone());
	builder.add_kernel_variable(process_pid.clone());
	builder.add_kernel_variable(timestamp.clone());

	let ctx = builder.build();

	let this_pid = std::process::id();
	let remove_this_pid_op = SelectKernelData::new(
		process_pid.clone(),
		BinaryOperator::Neq,
		Expr::uint(this_pid as u64),
		&ctx,
	)
	.into_op();

	let select_pid_op = if pid > 0 {
		Some(
			SelectKernelData::new(
				process_pid.clone(),
				BinaryOperator::Eq,
				Expr::uint(pid),
				&ctx,
			)
			.into_op(),
		)
	} else {
		None
	};

	let select_syscall_op = if syscall_num > 0 {
		Some(
			SelectKernelData::new(
				system_call.clone(),
				BinaryOperator::Eq,
				Expr::uint(syscall_num),
				&ctx,
			)
			.into_op(),
		)
	} else {
		None
	};

	let mut build_tuple = TupleBuilder::new();
	build_tuple.add_field(
		"timestamp".into(),
		&Kind::uint64_t(),
		&timestamp.variable(),
	);

	build_tuple.add_field(
		"syscall_number".into(),
		&Kind::uint64_t(),
		&system_call.variable(),
	);

	build_tuple.add_field(
		"pid".into(),
		&Kind::uint64_t(),
		&process_pid.variable(),
	);

	let build_tuple = build_tuple.build();
	let var = build_tuple.variable();
	let build_tuple = build_tuple.into_op();
	let output_op = PerfMapBufferAndOutput::new(&ctx, &var).into_op();

	let mut plan = ctx.plan();
	plan.add_op(remove_this_pid_op);

	if let Some(op) = select_pid_op {
		plan.add_op(op);
	}

	if let Some(op) = select_syscall_op {
		plan.add_op(op);
	}

	plan.add_op(build_tuple);
	plan.add_op(output_op.clone());

	let mut obj = plan.compile_and_load();

	// User space Plan

	// TODO:
	// This API is suckage. We can probably get a map consumer out of the
	// BpfObject....

	let perf_map = output_op.perf_map().unwrap();
	let buffer_t = output_op.buffer_kind().unwrap();
	let item_t = output_op.buffer_item_kind().unwrap();

	let map = obj.map_mut(perf_map.name()).unwrap();

	let schema = SchemaBuilder::new()
		.add_field("timestamp", SchemaKind::u64)
		.add_field("syscall_number", SchemaKind::u64)
		.add_field("pid", SchemaKind::u64)
		.build();

	// Userspace Operators
	let read_op = ReadFromPerfEventArray::new(
		map,
		&item_t,
		&buffer_t,
		&schema,
		lost_event_handler,
	)
	.to_op();

	let sink_op = SinkData::new(read_op);
	let rx = sink_op.receiver();
	let sink_op = sink_op.to_op();

	let mut user_plan = UserPlan::new(obj, sink_op);
	thread::spawn(move || {
		while let Ok(x) = rx.recv() {
			COUNT.fetch_add(x.include_count(), SeqCst);
		}
	});
	user_plan.execute();
}

fn q1_slow(pid: u64, syscall_num: u64) {
	let mut builder = KernelContextBuilder::new_syscall_enter_ctx();
	let ctx_var = builder.ctx_variable();

	let system_call = KernelVariable::new(
		&Kind::uint64_t(),
		&SysEnterField::SyscallNumber
			.as_kernel_schema()
			.as_kernel_variable_source(&ctx_var),
	);

	let process_pid = KernelVariable::new(
		&Kind::uint64_t(),
		&CurrentTaskField::Pid
			.as_kernel_schema()
			.as_kernel_variable_source(&ctx_var),
	);

	let timestamp = KernelVariable::new(
		&Kind::uint64_t(),
		&Timestamp::new()
			.as_kernel_schema()
			.as_kernel_variable_source(&ctx_var),
	);

	builder.add_kernel_variable(system_call.clone());
	builder.add_kernel_variable(process_pid.clone());
	builder.add_kernel_variable(timestamp.clone());

	let ctx = builder.build();

	let this_pid = std::process::id();
	let remove_this_pid_op = SelectKernelData::new(
		process_pid.clone(),
		BinaryOperator::Neq,
		Expr::uint(this_pid as u64),
		&ctx,
	)
	.into_op();

	let mut build_tuple = TupleBuilder::new();
	build_tuple.add_field(
		"timestamp".into(),
		&Kind::uint64_t(),
		&timestamp.variable(),
	);

	build_tuple.add_field(
		"syscall_number".into(),
		&Kind::uint64_t(),
		&system_call.variable(),
	);

	build_tuple.add_field(
		"pid".into(),
		&Kind::uint64_t(),
		&process_pid.variable(),
	);

	let build_tuple = build_tuple.build();
	let var = build_tuple.variable();
	let build_tuple = build_tuple.into_op();
	let output_op = PerfMapBufferAndOutput::new(&ctx, &var).into_op();

	let mut plan = ctx.plan();

	plan.add_op(remove_this_pid_op);
	plan.add_op(build_tuple);
	plan.add_op(output_op.clone());

	let mut obj = plan.compile_and_load();

	// User space Plan

	// TODO:
	// This API is suckage. We can probably get a map consumer out of the
	// BpfObject....

	let perf_map = output_op.perf_map().unwrap();
	let buffer_t = output_op.buffer_kind().unwrap();
	let item_t = output_op.buffer_item_kind().unwrap();

	let map = obj.map_mut(perf_map.name()).unwrap();

	let schema = SchemaBuilder::new()
		.add_field("timestamp", SchemaKind::u64)
		.add_field("syscall_number", SchemaKind::u64)
		.add_field("pid", SchemaKind::u64)
		.build();

	// Userspace Operators
	let mut op = ReadFromPerfEventArray::new(
		map,
		&item_t,
		&buffer_t,
		&schema,
		lost_event_handler,
	)
	.to_op();

	if pid > 0 {
		let transform = TransformOp::Init("pid".into());
		let compare =
			CompareOp::TransformEqScalar(transform, UserScalar::U64(pid));
		let filter_op = Select::new(compare, op).to_op();
		op = filter_op;
	}

	if syscall_num > 0 {
		let transform = TransformOp::Init("syscall_number".into());
		let compare = CompareOp::TransformEqScalar(
			transform,
			UserScalar::U64(syscall_num),
		);
		let filter_op = Select::new(compare, op).to_op();
		op = filter_op;
	}

	let sink_op = SinkData::new(op);
	let rx = sink_op.receiver();
	let op = sink_op.to_op();

	let mut user_plan = UserPlan::new(obj, op);
	thread::spawn(move || {
		while let Ok(x) = rx.recv() {
			COUNT.fetch_add(x.include_count(), SeqCst);
		}
	});

	user_plan.execute();
}

//fn q1_slow(pid: u64, syscall_num: u64) {
//	// Kernel space plan
//
//	let plan_output_t = Kind::cstruct(&[
//		("timestamp".into(), Kind::uint64_t()),
//		("syscall_number".into(), Kind::uint64_t()),
//		("pid".into(), Kind::uint64_t()),
//	]);
//
//	let mut kernel_ctx_builder =
//		BpfContext::SyscallEnter.kernel_context_builder();
//
//	let pid_schema = CurrentTaskField::Pid.as_kernel_schema();
//	let syscall_num_schema = SysEnterField::SyscallNumber.as_kernel_schema();
//	let timestamp_schema = Timestamp::new().as_kernel_schema();
//
//	kernel_ctx_builder.add_kernel_variable(syscall_num_schema);
//	kernel_ctx_builder.add_kernel_variable(timestamp_schema);
//	kernel_ctx_builder.add_kernel_variable(pid_schema);
//
//	let kernel_ctx = kernel_ctx_builder.build();
//
//	let mut plan = KernelPlan::from_parts(kernel_ctx.clone(), &plan_output_t);
//
//	// Maps
//	let buffer = KernelBpfMap::per_cpu_buffer(256, &plan_output_t);
//	let perf_array = KernelBpfMap::perf_event_array(&buffer.value_kind());
//
//	// Ops
//	let this_pid = std::process::id();
//	let remove_this_pid_op = SelectKernelData::new(
//		pid_schema,
//		BinaryOperator::Neq,
//		Expr::uint(this_pid as u64),
//		&kernel_ctx,
//	)
//	.into_op();
//
//	let append_timestamp_op = AppendKernelData::new(
//		&kernel_ctx,
//		timestamp_schema,
//		// TODO: We kind of hardcoded this access... need to clean up API
//		plan.output_variable().lvalue().member("timestamp"),
//	)
//	.into_op();
//
//	let append_syscall_number_op = AppendKernelData::new(
//		&kernel_ctx,
//		syscall_num_schema,
//		// TODO: We kind of hardcoded this access... need to clean up API
//		plan.output_variable().lvalue().member("syscall_number"),
//	)
//	.into_op();
//
//	let append_pid = AppendKernelData::new(
//		&kernel_ctx,
//		pid_schema,
//		// TODO: We kind of hardcoded this access... need to clean up API
//		plan.output_variable().lvalue().member("pid"),
//	)
//	.into_op();
//
//	let output_op = PerfMapBufferAndOutput::new(
//		&kernel_ctx,
//		&perf_array,
//		&buffer,
//		&plan.output_variable(),
//	)
//	.into_op();
//
//	plan.add_map(&buffer);
//	plan.add_map(&perf_array);
//
//	plan.add_op(remove_this_pid_op);
//	plan.add_op(append_timestamp_op);
//	plan.add_op(append_syscall_number_op);
//	plan.add_op(append_pid);
//	plan.add_op(output_op);
//
//	let mut obj = plan.compile_and_load();
//
//	// User space Plan
//	let map = obj.map_mut(perf_array.name()).unwrap();
//	let buffer_t = buffer.value_kind();
//	let item_t = plan_output_t.clone();
//	let schema = SchemaBuilder::new()
//		.add_field("timestamp", SchemaKind::u64)
//		.add_field("syscall_number", SchemaKind::u64)
//		.add_field("pid", SchemaKind::u64)
//		.build();
//
//	// Userspace Operators
//	let mut op = ReadFromPerfEventArray::new(
//		map,
//		&item_t,
//		&buffer_t,
//		&schema,
//		lost_event_handler,
//	)
//	.to_op();
//
//	if pid > 0 {
//		let transform = TransformOp::Init("pid".into());
//		let compare =
//			CompareOp::TransformEqScalar(transform, UserScalar::U64(pid));
//		let filter_op = Select::new(compare, op).to_op();
//		op = filter_op;
//	}
//
//	if syscall_num > 0 {
//		let transform = TransformOp::Init("syscall_number".into());
//		let compare = CompareOp::TransformEqScalar(
//			transform,
//			UserScalar::U64(syscall_num),
//		);
//		let filter_op = Select::new(compare, op).to_op();
//		op = filter_op;
//	}
//
//	let sink_op = SinkData::new(op);
//	let rx = sink_op.receiver();
//	let op = sink_op.to_op();
//
//	let mut user_plan = UserPlan::new(obj, op);
//	thread::spawn(move || {
//		while let Ok(x) = rx.recv() {
//			COUNT.fetch_add(x.include_count(), SeqCst);
//		}
//	});
//
//	user_plan.execute();
//}

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

	/// Target syscall number to monitor. Default = 0, captures all syscalls
	#[arg(short, long, default_value_t = false)]
	slow: bool,
}

fn main() {
	let args = Args::parse();
	thread::spawn(counter);
	q1(args.pid, args.syscall_number);
	//if args.slow {
	//	q1_slow(args.pid, args.syscall_number);
	//} else {
	//	q1(args.pid, args.syscall_number);
	//}
}
