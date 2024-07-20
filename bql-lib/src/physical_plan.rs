use crate::codegen::{
	Expr,
	Kind,
	Variable,
	IfBlock,
	BpfMap,
	Include,
	CodeGen,
	CodeUnit,
	Scalar,
	Function,
	FunctionBuilder,
	BpfProgram,
	BpfProgramDefinition,
	ScopeBlock,
	FunctionDeclaration,
	BinaryOperator,
	UnaryOperator,
	Lvalue,
	PerCpuArray,
};
use std::{
	sync::Arc,
	collections::HashMap
};

struct KernelPlan {
	ctx: KernelContext,
	plan: Vec<KernelOperator>,
	output: PlanOutput,
	maps: Vec<KernelBpfMap>,
}

impl KernelPlan {
	fn from_parts(
		ctx: KernelContext,
		output: &Kind,
	) -> Self {
		KernelPlan {
			ctx,
			output: PlanOutput::new(output.clone()),
			plan: Vec::new(),
			maps: Vec::new()
		}
	}

	fn add_op(&mut self, op: KernelOperator) {
		self.plan.push(op);
	}

	fn add_map(&mut self, map: &KernelBpfMap) {
		self.maps.push(map.clone());
	}

	fn add_filter_kernel_data_op(
		&mut self,
		kernel_data: KernelData,
		op: BinaryOperator,
		rhs: Expr,
		kernel_ctx: &KernelContext,
	) {
		let op = FilterKernelData::new(kernel_data, op, rhs, &self.ctx).into_op();
		self.plan.push(op);
	}

	fn add_append_kernel_data_op(
		&mut self,
		kernel_data: KernelData,
		field: &str,
	) {
		let dst = self.output.var.lvalue().member(field);
		let op = AppendKernelData::new(&self.ctx, kernel_data, dst).into_op();
		self.plan.push(op);
	}

	fn generate_code(&self) -> CodeGen {

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
			for unit in op.execute_op() {
				function_builder.append_code_unit(unit);
			}
		}

		let handle_sys_enter = function_builder.build();
		
		code.push(handle_sys_enter.definition().into());
		code
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
		vec.push(self.var.lvalue().assign(&Expr::cconst("{0}")).into());
		vec
	}
}

pub enum BpfContext {
	SyscallEnter
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
	fn new_syscall_enter_ctx() -> Self {
		let sysenter_args_t: Kind = Kind::array(&Kind::uint32_t(), 6);
		let ctx_t: Kind = Kind::cstruct(
				&[
				("pad".into(), Kind::uint64_t()),
				("syscall_number".into(), Kind::int64_t()),
				("args".into(), sysenter_args_t.clone()),
				],
		);
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
			name
		}
	}

	fn add_kernel_variable(&mut self, schema: KernelData) {
		self.kernel_variables.add_kernel_variable(schema);
	}

	fn build(self) -> KernelContext {
		let inner = InnerKernelContext {
			ctx_t: self.ctx_t,
			ctx_var: self.ctx_var,
			program_declaration: self.program_declaration,
			kernel_variables: self.kernel_variables,
			hook: self.hook,
			name: self.name,
		};
		KernelContext { inner: inner.into() }
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
		let mut f = FunctionBuilder::new(&self.inner.name, &self.inner.program_declaration);
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
	sources: HashMap<KernelData, KernelDataSource>
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
			KernelData::SysEnter(x) => x.make_assignment(&self.ctx_var, &self.variable),
			KernelData::CurrentTask(x) => x.make_assignment(&self.ctx_var, &self.variable),
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
	SyscallNumber
}

impl SysEnterField {
	fn make_variable(&self) -> Variable {
		match self {
			Self::SyscallNumber => Variable::new(&Kind::int(), None)
		}
	}

	fn make_assignment(&self, ctx: &Variable, dst: &Variable) -> CodeUnit {
		match self {
			Self::SyscallNumber => {
				dst.lvalue().assign(&ctx.expr().ref_member("syscall_number"))
			},
		}.into()
	}

	fn schema(&self) -> KernelData {
		KernelData::SysEnter(*self)
	}
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum CurrentTaskField {
	Pid
}

impl CurrentTaskField {
	fn make_variable(&self) -> Variable {
		match self {
			Self::Pid => Variable::new(&Kind::int(), None)
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
					func.call(Vec::new()).ref_member("pid").reference()
				];
				func.call(args)
			}
		}.into()
	}

	fn schema(&self) -> KernelData {
		KernelData::CurrentTask(*self)
	}
}

pub enum KernelOperator {
	FilterKernelData(FilterKernelData),
	AppendKernelData(AppendKernelData),
	PerfMapBufferAndOutput(PerfMapBufferAndOutput),
}

impl KernelOperator {
	pub fn execute_op(&self) -> Vec<CodeUnit> {
		match self {
			Self::FilterKernelData(x) => x.execute_op(),
			Self::AppendKernelData(x) => x.execute_op(),
			Self::PerfMapBufferAndOutput(x) => x.execute_op(),
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
	fn new(
		kernel_data: KernelData,
		op: BinaryOperator,
		rhs: Expr,
		kernel_ctx: &KernelContext,
	) -> Self {
		Self { kernel_data, op, rhs, kernel_ctx: kernel_ctx.clone(), }
	}

	fn into_op(self) -> KernelOperator {
		KernelOperator::FilterKernelData(self)
	}

	fn execute_op(&self) -> Vec<CodeUnit> {
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
	fn new(
		kernel_ctx: &KernelContext,
		kernel_data: KernelData,
		dst: Lvalue
	) -> Self {
		Self {
			kernel_data,
			kernel_ctx: kernel_ctx.clone(),
			dst
		}
	}

	fn into_op(self) -> KernelOperator {
		KernelOperator::AppendKernelData(self)
	}

	fn execute_op(&self) -> Vec<CodeUnit> {
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
	fn new(
		ctx: &KernelContext,
		perf_map: &KernelBpfMap,
		buffer_map: &KernelBpfMap,
		var: &Variable
	) -> Self {
		Self {
			perf_map: perf_map.clone(),
			buffer_map: buffer_map.clone(),
			var: var.clone(),
			ctx: ctx.clone(),
		}
	}

	fn into_op(self) -> KernelOperator {
		KernelOperator::PerfMapBufferAndOutput(self)
	}

	fn execute_op(&self) -> Vec<CodeUnit> {
		let mut result: Vec<CodeUnit> = Vec::new();

		let buffer_size = self.buffer_map.buffer_size().unwrap() as u64;
		let bpf_perf_event_output = Function::with_name("bpf_perf_event_output");
		let bpf_map_lookup_elem = Function::with_name("bpf_map_lookup_elem");
		let sizeof = Function::with_name("sizeof");

		let zero = Variable::new(&Kind::int(), None);
		result.push(zero.definition().into());
		result.push(zero.lvalue().assign(&Expr::int(0)).into());

		/*
		 * Lookup the buffer in the buffermap
		 */
		let buffer_ptr = Variable::new(&self.buffer_map.map_value_t.pointer(), None);
		result.push(buffer_ptr.definition().into());
		let expr = bpf_map_lookup_elem.call(
			vec![
				self.buffer_map.map.expr().reference(),
				zero.expr().reference()
			]
		);
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
			Expr::uint(buffer_size),
		);
		let mut block = ScopeBlock::new();
		let assign = buffer_ptr
			.lvalue()
			.ref_member("buffer")
			.offset(Expr::uint(1))
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
			Expr::uint(buffer_size)
		);
		let mut block = ScopeBlock::new();
		let expr = bpf_perf_event_output.call(
			vec![
					self.ctx.ctx_variable().expr().cast(Kind::void().pointer()),
					self.perf_map.map.expr().reference(),
					Expr::cconst("BPF_F_CURRENT_CPU"),
					buffer_ptr.expr(),
					sizeof.call(vec![buffer_ptr.expr().deref()]),
			]
		);
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
	PerCpuBuffer
}

#[derive(Clone)]
struct KernelBpfMap {
	map_value_t: Kind,
	map_key_t: Kind,
	map_t: Kind,
	map: Variable,
	map_type: BpfMapType,

	buffer_size: Option<usize>,
}

impl KernelBpfMap {
	fn perf_event_array(
		output_t: &Kind,
	) -> Self {
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

			buffer_size: None,
		}
	}

	fn per_cpu_buffer(sz: usize, buffered_kind: &Kind) -> Self {
		// There's always only one buffer in each CPU-specific map
		let map_key_t = Kind::__u32();

		// Store sz items in the buffer
		let map_value_t = Kind::cstruct(
			&[
				("length".into(), Kind::uint32_t()),
				("buffer".into(), Kind::array(buffered_kind, sz)),
			],
		);

		// Define map type
		let map_t = Kind::bpf_map(BpfMap::PerCpuArray(
			PerCpuArray::new(&map_key_t, &map_value_t, 1)
		));

		// Define map variable
		let map = Variable::new(&map_t, None);

		Self {
			map_value_t,
			map_key_t,
			map_t,
			map,
			map_type: BpfMapType::PerCpuBuffer,

			buffer_size: Some(sz),
		}
	}

	fn buffer_size(&self) -> Option<usize> {
		match self.map_type {
			BpfMapType::PerCpuBuffer => {
				self.buffer_size
			}
			_ => None,
		}
	}

	fn kind_definition(&self) -> CodeUnit {
		self.map_t.definition().into()
	}

	fn variable_definition(&self) -> CodeUnit {
		self.map.definition().into()
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test() {

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
		let perf_array = KernelBpfMap::perf_event_array(&buffer.map_value_t);

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
			plan.output.var.lvalue().member("syscall_number"), // TODO: This seems to be hardcoded
		).into_op();

		let output_op = PerfMapBufferAndOutput::new(
			&kernel_ctx,
			&perf_array,
			&buffer,
			&plan.output.var
		).into_op();

		plan.add_map(&buffer);
		plan.add_map(&perf_array);

		plan.add_op(filter_op);
		plan.add_op(append_syscall_number_op);
		plan.add_op(output_op);

		let code = plan.generate_code();
		println!("{}", code.generate_code());

	}
}
