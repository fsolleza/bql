use crate::bpf::{BpfCode, BpfObject};
use crate::codegen::{
	BinaryOperator, BpfMap, BpfProgram, BpfProgramDefinition, CodeGen,
	CodeUnit, Expr, Function, FunctionBuilder, FunctionDeclaration, IfBlock,
	Include, Kind, Lvalue, PerCpuArray, Scalar, ScopeBlock, UnaryOperator,
	Variable,
};
use crossbeam::channel::{unbounded, Receiver, Sender};

use std::{collections::HashMap, sync::Arc};

pub struct KernelPlan {
	ctx: KernelContext,
	plan: Vec<KernelOperator>,
	output: PlanOutput,
	maps: Vec<KernelBpfMap>,
	code: Option<BpfCode>,
}

impl KernelPlan {
	pub fn output_variable(&self) -> Variable {
		self.output.var.clone()
	}

	pub fn from_parts(ctx: KernelContext, output: &Kind) -> Self {
		KernelPlan {
			ctx,
			output: PlanOutput::new(output.clone()),
			plan: Vec::new(),
			maps: Vec::new(),
			code: None,
		}
	}

	pub fn add_op(&mut self, op: KernelOperator) {
		self.plan.push(op);
	}

	pub fn add_map(&mut self, map: &KernelBpfMap) {
		self.maps.push(map.clone());
	}

	pub fn emit_code(&mut self) -> &BpfCode {
		if self.code.is_none() {
			let mut code = CodeGen::new();

			code.push(Include::FilePath("vmlinux.h".into()).into());
			code.push(Include::Library("bpf/bpf_core_read.h".into()).into());
			code.push(Include::Library("bpf/bpf_helpers.h".into()).into());

			// Define context types
			code.push(self.ctx.ctx_definition());

			// Define output type
			code.push(self.output.kind_definition());

			// Define all map types and map variables
			for map in self.maps.iter() {
				code.push(map.kind_definition());
				code.push(map.variable_definition());
			}

			// Build program
			let mut function_builder = self.ctx.program_builder();

			// We always define the output struct first
			for unit in self.output.variable_definition() {
				function_builder.append_code_unit(unit);
			}

			// Then execute every op sequentially
			for op in self.plan.iter() {
				for unit in op.emit_code() {
					function_builder.append_code_unit(unit);
				}
			}

			let handle_sys_enter = function_builder.build();

			code.push(handle_sys_enter.definition().into());
			code.push(CodeUnit::BpfLicense);
			self.code = Some(BpfCode::new(&code.emit_code()));
		}
		self.code.as_ref().unwrap()
	}

	pub fn compile_and_load(&mut self) -> BpfObject {
		self.emit_code().compile_and_load()
	}
}

pub struct PlanOutput {
	kind: Kind,
	var: Variable,
}

impl PlanOutput {
	pub fn new(kind: Kind) -> Self {
		let var = Variable::new(&kind, None);
		Self { var, kind }
	}

	pub fn kind_definition(&self) -> CodeUnit {
		self.kind.definition().into()
	}

	pub fn variable_definition(&self) -> Vec<CodeUnit> {
		let mut vec: Vec<CodeUnit> = Vec::new();
		vec.push(self.var.definition().into());
		vec
	}
}

pub enum BpfContext {
	SyscallEnter,
}

impl BpfContext {
	pub fn kernel_context_builder(&self) -> KernelContextBuilder {
		match self {
			Self::SyscallEnter => KernelContextBuilder::new_syscall_enter_ctx(),
		}
	}
}

pub struct KernelContextBuilder {
	ctx_t: Kind,
	ctx_var: Variable,
	program_declaration: FunctionDeclaration,
	kernel_variables: KernelVariables,
	hook: String,
	name: String,
}

impl KernelContextBuilder {
	pub fn new_syscall_enter_ctx() -> Self {
		let sysenter_args_t: Kind = Kind::array(&Kind::uint32_t(), 6);
		let ctx_t: Kind = Kind::cstruct(&[
			("pad".into(), Kind::uint64_t()),
			("syscall_number".into(), Kind::int64_t()),
			("args".into(), sysenter_args_t.clone()),
		]);
		let program_declaration =
			FunctionDeclaration::new(&Kind::int(), vec![ctx_t.pointer()]);
		let ctx_var = program_declaration.get_arg(0).unwrap();
		let kernel_variables = KernelVariables::new(&ctx_var);
		let hook = String::from("tp/raw_syscalls/sys_enter");
		let name = String::from("handle_sys_enter");

		Self {
			ctx_t,
			ctx_var,
			program_declaration,
			kernel_variables,
			hook,
			name,
		}
	}

	pub fn add_kernel_variable(&mut self, schema: KernelData) {
		self.kernel_variables.add_kernel_variable(schema);
	}

	pub fn build(self) -> KernelContext {
		let inner = InnerKernelContext {
			ctx_t: self.ctx_t,
			ctx_var: self.ctx_var,
			program_declaration: self.program_declaration,
			kernel_variables: self.kernel_variables,
			hook: self.hook,
			name: self.name,
		};
		KernelContext {
			inner: inner.into(),
		}
	}
}

#[derive(Clone)]
pub struct KernelContext {
	inner: Arc<InnerKernelContext>,
}

impl KernelContext {
	fn ctx_definition(&self) -> CodeUnit {
		self.inner.ctx_t.definition().into()
	}

	fn program_builder(&self) -> BpfProgramBuilder {
		let mut f = FunctionBuilder::new(
			&self.inner.name,
			&self.inner.program_declaration,
		);
		for unit in self.inner.kernel_variables.initialize_variables() {
			f.append_code_unit(unit);
		}

		BpfProgramBuilder {
			inner: self.inner.clone(),
			function_builder: f,
		}
	}

	fn get_kernel_variable(&self, kernel_data: &KernelData) -> Variable {
		self.inner.kernel_variables.get_variable(kernel_data)
	}

	fn ctx_variable(&self) -> Variable {
		self.inner.ctx_var.clone()
	}
}

pub struct InnerKernelContext {
	ctx_t: Kind,
	ctx_var: Variable,
	program_declaration: FunctionDeclaration,
	kernel_variables: KernelVariables,
	hook: String,
	name: String,
}

pub struct BpfProgramBuilder {
	inner: Arc<InnerKernelContext>,
	function_builder: FunctionBuilder,
}

impl BpfProgramBuilder {
	pub fn append_code_unit(&mut self, code: CodeUnit) {
		self.function_builder.append_code_unit(code);
	}

	pub fn build(mut self) -> BpfProgram {
		self.append_code_unit(CodeUnit::Return(Expr::uint(0)));
		let func = self.function_builder.build();
		BpfProgram::from_function(func, &self.inner.hook)
	}
}

pub struct KernelVariables {
	ctx_var: Variable,
	sources: HashMap<KernelData, KernelDataSource>,
}

impl KernelVariables {
	pub fn new(ctx_var: &Variable) -> Self {
		KernelVariables {
			ctx_var: ctx_var.clone(),
			sources: HashMap::new(),
		}
	}

	pub fn add_kernel_variable(&mut self, schema: KernelData) {
		let source = KernelDataSource::new(&self.ctx_var, schema);
		self.sources.insert(schema, source);
	}

	pub fn get_variable(&self, source: &KernelData) -> Variable {
		self.sources.get(source).unwrap().variable.clone()
	}

	pub fn initialize_variables(&self) -> Vec<CodeUnit> {
		let mut units: Vec<CodeUnit> = Vec::new();
		for (_, k) in self.sources.iter() {
			units.push(k.variable.definition().into());
			units.push(k.make_assignment());
		}
		units
	}
}

pub struct KernelDataSource {
	ctx_var: Variable,
	variable: Variable,
	source: KernelData,
}

impl KernelDataSource {
	fn new(ctx_var: &Variable, source: KernelData) -> Self {
		Self {
			ctx_var: ctx_var.clone(),
			variable: source.make_variable(),
			source,
		}
	}

	fn make_assignment(&self) -> CodeUnit {
		match &self.source {
			KernelData::SysEnter(x) => {
				x.make_assignment(&self.ctx_var, &self.variable)
			}
			KernelData::CurrentTask(x) => {
				x.make_assignment(&self.ctx_var, &self.variable)
			}
		}
	}
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum KernelData {
	SysEnter(SysEnterField),
	CurrentTask(CurrentTaskField),
}

impl KernelData {
	fn make_variable(&self) -> Variable {
		match self {
			Self::SysEnter(x) => x.make_variable(),
			Self::CurrentTask(x) => x.make_variable(),
		}
	}
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum SysEnterField {
	SyscallNumber,
}

impl SysEnterField {
	fn make_variable(&self) -> Variable {
		match self {
			Self::SyscallNumber => Variable::new(&Kind::int(), None),
		}
	}

	fn make_assignment(&self, ctx: &Variable, dst: &Variable) -> CodeUnit {
		match self {
			Self::SyscallNumber => dst
				.lvalue()
				.assign(&ctx.expr().ref_member("syscall_number")),
		}
		.into()
	}

	pub fn schema(&self) -> KernelData {
		KernelData::SysEnter(*self)
	}
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum CurrentTaskField {
	Pid,
}

impl CurrentTaskField {
	fn make_variable(&self) -> Variable {
		match self {
			Self::Pid => Variable::new(&Kind::int(), None),
		}
	}

	fn make_assignment(&self, _: &Variable, dst: &Variable) -> CodeUnit {
		let func = Function::with_name("bpf_get_current_task");
		let read = Function::with_name("bpf_probe_read");
		let sizeof = Function::with_name("sizeof");
		match self {
			Self::Pid => {
				let args = vec![
					dst.expr().reference(),
					sizeof.call(vec![dst.clone().expr()]),
					func.call(Vec::new())
						.cast(Kind::other("struct task_struct *".into()))
						.ref_member("pid")
						.reference(),
				];
				read.call(args)
			}
		}
		.into()
	}

	pub fn schema(&self) -> KernelData {
		KernelData::CurrentTask(*self)
	}
}

pub enum KernelOperator {
	FilterKernelData(FilterKernelData),
	AppendKernelData(AppendKernelData),
	PerfMapBufferAndOutput(PerfMapBufferAndOutput),
}

impl KernelOperator {
	pub fn emit_code(&self) -> Vec<CodeUnit> {
		match self {
			Self::FilterKernelData(x) => x.emit_code(),
			Self::AppendKernelData(x) => x.emit_code(),
			Self::PerfMapBufferAndOutput(x) => x.emit_code(),
		}
	}
}

pub struct FilterKernelData {
	kernel_data: KernelData,
	op: BinaryOperator,
	rhs: Expr,
	kernel_ctx: KernelContext,
}

impl FilterKernelData {
	pub fn new(
		kernel_data: KernelData,
		op: BinaryOperator,
		rhs: Expr,
		kernel_ctx: &KernelContext,
	) -> Self {
		Self {
			kernel_data,
			op,
			rhs,
			kernel_ctx: kernel_ctx.clone(),
		}
	}

	pub fn into_op(self) -> KernelOperator {
		KernelOperator::FilterKernelData(self)
	}

	fn emit_code(&self) -> Vec<CodeUnit> {
		let variable = self.kernel_ctx.get_kernel_variable(&self.kernel_data);
		let filter = Expr::binary(variable.expr(), self.op, self.rhs.clone());
		let mut filter_block = ScopeBlock::new();
		filter_block.push(CodeUnit::Return(Expr::uint(0).into()).into());
		vec![IfBlock::from_parts(filter, filter_block).into()]
	}
}

pub struct AppendKernelData {
	kernel_data: KernelData,
	kernel_ctx: KernelContext,
	dst: Lvalue,
}

impl AppendKernelData {
	pub fn new(
		kernel_ctx: &KernelContext,
		kernel_data: KernelData,
		dst: Lvalue,
	) -> Self {
		Self {
			kernel_data,
			kernel_ctx: kernel_ctx.clone(),
			dst,
		}
	}

	pub fn into_op(self) -> KernelOperator {
		KernelOperator::AppendKernelData(self)
	}

	fn emit_code(&self) -> Vec<CodeUnit> {
		let variable = self.kernel_ctx.get_kernel_variable(&self.kernel_data);
		vec![self.dst.assign(&variable.expr()).into()]
	}
}

pub struct PerfMapBufferAndOutput {
	perf_map: KernelBpfMap,
	buffer_map: KernelBpfMap,
	var: Variable,
	ctx: KernelContext,
}

impl PerfMapBufferAndOutput {
	pub fn new(
		ctx: &KernelContext,
		perf_map: &KernelBpfMap,
		buffer_map: &KernelBpfMap,
		var: &Variable,
	) -> Self {
		Self {
			perf_map: perf_map.clone(),
			buffer_map: buffer_map.clone(),
			var: var.clone(),
			ctx: ctx.clone(),
		}
	}

	pub fn into_op(self) -> KernelOperator {
		KernelOperator::PerfMapBufferAndOutput(self)
	}

	fn emit_code(&self) -> Vec<CodeUnit> {
		let mut result: Vec<CodeUnit> = Vec::new();

		let buffer_capacity = self.buffer_map.buffer_capacity().unwrap() as u64;
		let bpf_perf_event_output =
			Function::with_name("bpf_perf_event_output");
		let bpf_map_lookup_elem = Function::with_name("bpf_map_lookup_elem");
		let sizeof = Function::with_name("sizeof");

		let zero = Variable::new(&Kind::int(), None);
		result.push(zero.definition().into());
		result.push(zero.lvalue().assign(&Expr::int(0)).into());

		/*
		 * Lookup the buffer in the buffermap
		 */
		let buffer_ptr =
			Variable::new(&self.buffer_map.map_value_t.pointer(), None);
		result.push(buffer_ptr.definition().into());
		let expr = bpf_map_lookup_elem.call(vec![
			self.buffer_map.map.expr().reference(),
			zero.expr().reference(),
		]);
		let assign = buffer_ptr.lvalue().assign(&expr);
		result.push(assign.into());

		/*
		 * Check if the buffer is null
		 */
		let buffer_check = Expr::unary(buffer_ptr.expr(), UnaryOperator::Not);
		let mut check_block = ScopeBlock::new();
		check_block.push(CodeUnit::Return(Expr::uint(0)));
		result.push(IfBlock::from_parts(buffer_check, check_block).into());

		/*
		 * Check if the buffer length is < length
		 * if (buffer->length < length) {
		 *     buffer->buffer[buffer->length] = e;
		 *     buffer->length += 1;
		 * }
		 */
		let buffer_len_check = Expr::binary(
			buffer_ptr.expr().ref_member("length"),
			BinaryOperator::Lt,
			Expr::uint(buffer_capacity),
		);
		let mut block = ScopeBlock::new();
		let assign = buffer_ptr
			.lvalue()
			.ref_member("buffer")
			.offset(buffer_ptr.expr().ref_member("length"))
			.assign(&self.var.expr());
		block.push(assign.into());
		let assign = buffer_ptr
			.lvalue()
			.ref_member("length")
			.add_assign(Expr::uint(1));
		block.push(assign.into());
		result.push(IfBlock::from_parts(buffer_len_check, block).into());

		/*
		 * Send the buffer to userspace using the event buffer
		 *
		 * if (buffer->length == 256) {
		 *   bpf_perf_event_output(
		 *     (void *)ctx,
		 *     &perf_buffer,
		 *     BPF_F_CURRENT_CPU,
		 *     buffer,
		 *     sizeof(*buffer)
		 *   );
		 *   buffer->length = 0;
		 * }
		 *
		 */
		let buffer_full_check = Expr::binary(
			buffer_ptr.expr().ref_member("length"),
			BinaryOperator::Eq,
			Expr::uint(buffer_capacity),
		);
		let mut block = ScopeBlock::new();
		let expr = bpf_perf_event_output.call(vec![
			self.ctx.ctx_variable().expr().cast(Kind::void().pointer()),
			self.perf_map.map.expr().reference(),
			Expr::cconst("BPF_F_CURRENT_CPU"),
			buffer_ptr.expr(),
			sizeof.call(vec![buffer_ptr.expr().deref()]),
		]);
		block.push(expr.into());

		let assign = buffer_ptr
			.lvalue()
			.ref_member("length")
			.assign(&Expr::uint(0));
		block.push(assign.into());

		result.push(IfBlock::from_parts(buffer_full_check, block).into());

		result
	}
}

#[derive(Clone)]
enum BpfMapType {
	PerfEventArray,
	PerCpuBuffer,
}

#[derive(Clone)]
pub struct KernelBpfMap {
	map_value_t: Kind,
	map_key_t: Kind,
	map_t: Kind,
	map: Variable,
	map_type: BpfMapType,

	buffer_capacity: Option<usize>,
	buffer_kind: Option<Kind>,
}

impl KernelBpfMap {
	pub fn name(&self) -> String {
		self.map.name()
	}

	pub fn value_kind(&self) -> Kind {
		self.map_value_t.clone()
	}

	pub fn key_kind(&self) -> Kind {
		self.map_key_t.clone()
	}

	pub fn map_kind(&self) -> Kind {
		self.map_t.clone()
	}

	pub fn map_variable(&self) -> Variable {
		self.map.clone()
	}

	pub fn perf_event_array(output_t: &Kind) -> Self {
		let map_t = Kind::bpf_map(BpfMap::perf_event_array(
			Scalar::cconst("sizeof(int)"),
			Scalar::cconst("sizeof(int)"),
		));
		let map_value_t = Kind::int();
		let map_key_t = Kind::int();
		let map = Variable::new(&map_t, None);
		Self {
			map_value_t,
			map_key_t,
			map_t,
			map,
			map_type: BpfMapType::PerfEventArray,

			buffer_capacity: None,
			buffer_kind: None,
		}
	}

	pub fn map_value_kind(&self) -> Kind {
		self.map_value_t.clone()
	}

	pub fn buffered_kind(&self) -> Option<Kind> {
		self.buffer_kind.clone()
	}

	pub fn per_cpu_buffer(sz: usize, buffered_kind: &Kind) -> Self {
		// There's always only one buffer in each CPU-specific map
		let map_key_t = Kind::__u32();

		// Store sz items in the buffer
		let map_value_t = Kind::cstruct(&[
			("length".into(), Kind::uint32_t()),
			("buffer".into(), Kind::array(buffered_kind, sz)),
		]);

		// Define map type
		let map_t = Kind::bpf_map(BpfMap::PerCpuArray(PerCpuArray::new(
			&map_key_t,
			&map_value_t,
			1,
		)));

		// Define map variable
		let map = Variable::new(&map_t, None);

		Self {
			map_value_t,
			map_key_t,
			map_t,
			map,
			map_type: BpfMapType::PerCpuBuffer,

			buffer_capacity: Some(sz),
			buffer_kind: Some(buffered_kind.clone()),
		}
	}

	fn buffer_capacity(&self) -> Option<usize> {
		self.buffer_capacity
	}

	fn kind_definition(&self) -> CodeUnit {
		self.map_t.definition().into()
	}

	fn variable_definition(&self) -> CodeUnit {
		self.map.definition().into()
	}
}
