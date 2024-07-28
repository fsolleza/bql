use crate::bpf::{BpfCode, BpfObject};
use crate::codegen::{
	BinaryOperator, BpfMap, BpfProgram, BpfProgramDefinition, CodeGen,
	CodeUnit, Expr, Function, FunctionBuilder, FunctionDeclaration, IfBlock,
	Include, Kind, Lvalue, LvalueAssignment, PerCpuArray, Scalar, ScopeBlock,
	UnaryOperator, Variable,
};
use crossbeam::channel::{unbounded, Receiver, Sender};

use std::{collections::HashMap, sync::Arc};

//pub type KernelScalar = Scalar;

pub struct KernelPlan {
	ctx: KernelContext,
	plan: Vec<KernelOperator>,
	maps: Vec<KernelBpfMap>,
	code: Option<BpfCode>,
}

impl KernelPlan {
	//pub fn output_variable(&self) -> Variable {
	//	self.output.var.clone()
	//}

	pub fn new(ctx: KernelContext) -> Self {
		Self {
			ctx,
			plan: Vec::new(),
			maps: Vec::new(),
			code: None,
		}
	}

	pub fn add_op(&mut self, op: KernelOperator) {
		self.plan.push(op);
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
			//code.push(self.output.kind_definition());

			// Define all map types and map variables
			for op in self.plan.iter() {
				code.append(&op.emit_definition_code());
			}

			// Build program
			let mut function_builder = self.ctx.program_builder();

			// Then execute every op sequentially
			for op in self.plan.iter() {
				for unit in op.emit_execution_code() {
					function_builder.append_code_unit(unit);
				}
			}

			let handle_sys_enter: BpfProgram = function_builder.build();

			code.push(CodeUnit::Comment("Begin BPF Program".into()));
			code.push(handle_sys_enter.definition().into());

			code.push(CodeUnit::Comment("Required License".into()));
			code.push(CodeUnit::BpfLicense);

			self.code = Some(BpfCode::new(&code.emit_code()));
		}
		self.code.as_ref().unwrap()
	}

	pub fn compile_and_load(&mut self) -> BpfObject {
		self.emit_code().compile_and_load()
	}
}

pub struct PerfMapOutput {
	kind: Kind,
	var: Variable,
}

impl PerfMapOutput {
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
	kernel_variables: Vec<KernelVariable>,
	hook: String,
	name: String,
	//maps: HashMap<String, KernelBpfMap>,
	//perf_map_output: Option<PerfMapOutput>,
}

impl KernelContextBuilder {
	pub fn ctx_variable(&self) -> Variable {
		self.ctx_var.clone()
	}

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
		let kernel_variables = Vec::new();
		let hook = String::from("tp/raw_syscalls/sys_enter");
		let name = String::from("handle_sys_enter");

		Self {
			ctx_t,
			ctx_var,
			program_declaration,
			kernel_variables,
			hook,
			name,
			//maps,
		}
	}

	pub fn add_kernel_variable(&mut self, v: KernelVariable) {
		self.kernel_variables.push(v);
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

	fn plan(&self) -> KernelPlan {
		KernelPlan::new(self.clone())
	}

	fn program_builder(&self) -> BpfProgramBuilder {
		let mut f = FunctionBuilder::new(
			&self.inner.name,
			&self.inner.program_declaration,
		);

		for var in self.inner.kernel_variables.iter() {
			for unit in var.emit_variable_definition() {
				f.append_code_unit(unit);
			}
		}

		BpfProgramBuilder {
			inner: self.inner.clone(),
			function_builder: f,
		}
	}

	fn ctx_variable(&self) -> Variable {
		self.inner.ctx_var.clone()
	}
}

pub struct InnerKernelContext {
	ctx_t: Kind,
	ctx_var: Variable,
	program_declaration: FunctionDeclaration,
	kernel_variables: Vec<KernelVariable>,
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

#[derive(Clone)]
pub enum KernelVariableSource {
	KernelSchema { ctx: Variable, schema: KernelSchema },
	Expr(Expr),
}

impl KernelVariableSource {
	pub fn assign(&self, var: &Variable) -> Vec<CodeUnit> {
		match self {
			Self::Expr(e) => vec![var.lvalue().assign(e).into()],
			Self::KernelSchema { ctx, schema } => {
				schema.make_assignment(ctx, var)
			}
		}
	}

	pub fn from_kernel_schema(ctx: &Variable, schema: KernelSchema) -> Self {
		Self::KernelSchema {
			ctx: ctx.clone(),
			schema,
		}
	}

	pub fn from_expr(expr: &Expr) -> Self {
		Self::Expr(expr.clone())
	}
}

trait AsKernelVariableSource {
	fn as_kernel_variable_source(&self, ctx: &Variable)
		-> KernelVariableSource;
}

impl AsKernelVariableSource for KernelSchema {
	fn as_kernel_variable_source(
		&self,
		ctx: &Variable,
	) -> KernelVariableSource {
		KernelVariableSource::KernelSchema {
			ctx: ctx.clone(),
			schema: self.clone(),
		}
	}
}

impl AsKernelVariableSource for Expr {
	fn as_kernel_variable_source(&self, _: &Variable) -> KernelVariableSource {
		KernelVariableSource::Expr(self.clone())
	}
}

#[derive(Clone)]
pub struct KernelVariable {
	var: Variable,
	kind: Kind,
	source: KernelVariableSource,
}

impl KernelVariable {
	pub fn variable(&self) -> Variable {
		self.var.clone()
	}

	pub fn new(kind: &Kind, source: &KernelVariableSource) -> Self {
		let var = Variable::new(kind, None);
		Self {
			var,
			kind: kind.clone(),
			source: source.clone(),
		}
	}

	pub fn emit_variable_definition(&self) -> Vec<CodeUnit> {
		let mut units: Vec<CodeUnit> = Vec::new();
		units.push(self.var.definition().into());
		units.append(&mut self.source.assign(&self.var));
		units
	}
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub enum KernelSchema {
	SysEnter(SysEnterField),
	CurrentTask(CurrentTaskField),
	Timestamp(Timestamp),
}

impl KernelSchema {
	fn make_variable(&self) -> Variable {
		match self {
			Self::SysEnter(x) => x.make_variable(),
			Self::CurrentTask(x) => x.make_variable(),
			Self::Timestamp(x) => x.make_variable(),
		}
	}

	fn make_assignment(&self, ctx: &Variable, var: &Variable) -> Vec<CodeUnit> {
		match &self {
			KernelSchema::SysEnter(x) => x.make_assignment(ctx, var),
			KernelSchema::CurrentTask(x) => x.make_assignment(ctx, var),
			KernelSchema::Timestamp(x) => x.make_assignment(var),
		}
	}
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct Timestamp {}

impl Timestamp {
	pub fn new() -> Self {
		Timestamp {}
	}

	fn make_variable(&self) -> Variable {
		Variable::new(&Kind::uint64_t(), None)
	}

	fn make_assignment(&self, dst: &Variable) -> Vec<CodeUnit> {
		let func = Function::with_name("bpf_ktime_get_ns");
		vec![dst.lvalue().assign(&func.call(vec![])).into()]
	}

	pub fn as_kernel_schema(&self) -> KernelSchema {
		KernelSchema::Timestamp(*self)
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

	fn make_assignment(&self, ctx: &Variable, dst: &Variable) -> Vec<CodeUnit> {
		match self {
			Self::SyscallNumber => vec![dst
				.lvalue()
				.assign(&ctx.expr().ref_member("syscall_number"))
				.into()],
		}
	}

	pub fn as_kernel_schema(&self) -> KernelSchema {
		KernelSchema::SysEnter(*self)
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

	fn make_assignment(&self, _: &Variable, dst: &Variable) -> Vec<CodeUnit> {
		let func = Function::with_name("bpf_get_current_task");
		let read = Function::with_name("bpf_probe_read");
		let sizeof = Function::with_name("sizeof");
		vec![match self {
			Self::Pid => {
				let args = vec![
					dst.expr().reference(),
					sizeof.call(vec![dst.clone().expr()]),
					func.call(Vec::new())
						.cast(Kind::other("struct task_struct *".into()))
						.ref_member("tgid")
						.reference(),
				];
				read.call(args)
			}
		}
		.into()]
	}

	pub fn as_kernel_schema(&self) -> KernelSchema {
		KernelSchema::CurrentTask(*self)
	}
}

pub enum KernelOperator {
	SelectKernelData(SelectKernelData),
	PerfMapBufferAndOutput(PerfMapBufferAndOutput),
	BuildTupleStruct(BuildTupleStruct),
}

impl KernelOperator {
	pub fn emit_execution_code(&self) -> Vec<CodeUnit> {
		match self {
			Self::SelectKernelData(x) => x.emit_execution_code(),
			Self::PerfMapBufferAndOutput(x) => x.emit_execution_code(),
			Self::BuildTupleStruct(x) => x.emit_execution_code(),
		}
	}

	pub fn emit_definition_code(&self) -> Vec<CodeUnit> {
		match self {
			Self::SelectKernelData(x) => x.emit_definition_code(),
			Self::PerfMapBufferAndOutput(x) => x.emit_definition_code(),
			Self::BuildTupleStruct(x) => x.emit_definition_code(),
		}
	}

	pub fn emit_initialization_code(&self) -> Vec<CodeUnit> {
		unimplemented!()
	}
}

pub struct SelectKernelData {
	kernel_variable: KernelVariable,
	op: BinaryOperator,
	rhs: Expr,
	kernel_ctx: KernelContext,
}

impl SelectKernelData {
	pub fn new(
		kernel_variable: KernelVariable,
		op: BinaryOperator,
		rhs: Expr,
		kernel_ctx: &KernelContext,
	) -> Self {
		Self {
			kernel_variable,
			op,
			rhs,
			kernel_ctx: kernel_ctx.clone(),
		}
	}

	pub fn into_op(self) -> KernelOperator {
		KernelOperator::SelectKernelData(self)
	}

	fn emit_definition_code(&self) -> Vec<CodeUnit> {
		Vec::new()
	}

	fn emit_execution_code(&self) -> Vec<CodeUnit> {
		let variable = self.kernel_variable.variable();
		let filter = Expr::unary(
			Expr::binary(variable.expr(), self.op, self.rhs.clone()),
			UnaryOperator::Not,
		);
		let mut filter_block = ScopeBlock::new();
		filter_block.push(CodeUnit::Return(Expr::uint(0).into()).into());
		vec![
			CodeUnit::Comment("Execution for SelectKernelData operator".into()),
			IfBlock::from_parts(filter, filter_block).into(),
		]
	}
}

pub struct TupleBuilder {
	fields: Vec<(String, Kind, Variable)>,
}

impl TupleBuilder {
	pub fn new() -> Self {
		Self { fields: Vec::new() }
	}

	pub fn add_field(&mut self, field: &str, kind: &Kind, var: &Variable) {
		self.fields.push((field.into(), kind.clone(), var.clone()))
	}

	pub fn build(self) -> BuildTupleStruct {
		let mut fields = Vec::new();

		for (n, k, v) in self.fields.iter() {
			fields.push((n.into(), k.clone()));
		}

		let kind = Kind::cstruct(&fields);
		let variable = Variable::new(&kind, None);

		BuildTupleStruct {
			variable,
			kind,
			fields: self.fields,
		}
	}
}

pub struct BuildTupleStruct {
	fields: Vec<(String, Kind, Variable)>,
	kind: Kind,
	variable: Variable,
}

impl BuildTupleStruct {
	pub fn variable(&self) -> Variable {
		self.variable.clone()
	}

	pub fn into_op(self) -> KernelOperator {
		KernelOperator::BuildTupleStruct(self)
	}

	fn emit_definition_code(&self) -> Vec<CodeUnit> {
		vec![
			CodeUnit::Comment("Struct for a BuildTupleStruct operator".into()),
			self.kind.definition().into(),
		]
	}

	pub fn emit_execution_code(&self) -> Vec<CodeUnit> {
		let mut code_units: Vec<CodeUnit> = Vec::new();
		code_units.push(CodeUnit::Comment(
			"Execution for BuildTupleStruct operator".into(),
		));
		code_units.push(self.variable.definition().into());
		for (n, _, v) in self.fields.iter() {
			let e = v.expr();
			let unit = self.variable.lvalue().member(&n).assign(&e);
			code_units.push(unit.into());
		}
		code_units
	}
}

//pub struct AppendKernelData {
//	kernel_data: KernelSchema,
//	kernel_ctx: KernelContext,
//	dst: Lvalue,
//}
//
//impl AppendKernelData {
//	pub fn new(
//		kernel_ctx: &KernelContext,
//		kernel_data: KernelSchema,
//		dst: Lvalue,
//	) -> Self {
//		Self {
//			kernel_data,
//			kernel_ctx: kernel_ctx.clone(),
//			dst,
//		}
//	}
//
//	pub fn into_op(self) -> KernelOperator {
//		KernelOperator::AppendKernelData(self)
//	}
//
//	fn emit_execution_code(&self) -> Vec<CodeUnit> {
//		let variable = self.kernel_ctx.get_kernel_variable(&self.kernel_data);
//		vec![self.dst.assign(&variable.expr()).into()]
//	}
//}

pub enum KernelGroupBy {
	Count,
}

//pub struct BpfHashMapGroupBy {
//	hash_map: KernelBpfMap,
//	hashmap_var: Variable,
//	ctx: KernelContext,
//	group_by: KernelGroupBy,
//	key: Variable,
//}
//
//impl BpfHashMapGroupBy {
//	pub fn new(
//		ctx: &KernelContext,
//		hash_map: &KernelBpfMap,
//		hashmap_var: &Variable,
//		source_var: &Variable,
//		key: &Variable,
//		group_by: KernelGroupBy,
//	) -> Self {
//		Self {
//			hash_map: hash_map.clone(),
//			var: var.clone(),
//			ctx: ctx.clone(),
//			source_var: ctx.clone(),
//			key: key.clone(),
//			group_by,
//		}
//	}
//
//	fn emit_execution_code(&self) -> Vec<CodeUnit> {
//		unimplemented!()
//	}
//}

pub struct PerfMapBufferAndOutput {
	perf_map: KernelBpfMap,
	buffer_map: KernelBpfMap,
	var: Variable,
	ctx: KernelContext,
}

impl PerfMapBufferAndOutput {
	pub fn new(ctx: &KernelContext, var: &Variable) -> Self {
		let var = var.clone();
		let buffer_map = KernelBpfMap::per_cpu_buffer(256, &var.kind());
		let perf_map = KernelBpfMap::perf_event_array(&buffer_map.value_kind());

		Self {
			perf_map,
			buffer_map,
			var,
			ctx: ctx.clone(),
		}
	}

	pub fn into_op(self) -> KernelOperator {
		KernelOperator::PerfMapBufferAndOutput(self)
	}

	fn emit_definition_code(&self) -> Vec<CodeUnit> {
		let mut v = Vec::new();
		v.push(CodeUnit::Comment(
			"Definitions for PerfMapBufferOutput operator".into(),
		));
		v.push(self.perf_map.kind_definition().into());
		v.push(self.perf_map.variable_definition().into());
		v.push(self.buffer_map.kind_definition().into());
		v.push(self.buffer_map.variable_definition().into());
		v
	}

	fn emit_execution_code(&self) -> Vec<CodeUnit> {
		let mut result: Vec<CodeUnit> = Vec::new();
		result.push(CodeUnit::Comment(
			"Execution for PerfMapBufferOutput operator".into(),
		));

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

#[cfg(test)]
mod test {
	use super::*;
	use clang_format::clang_format;

	#[test]
	fn kernel_plan_test() {
		let mut builder = KernelContextBuilder::new_syscall_enter_ctx();
		let ctx_var = builder.ctx_variable();

		let target_pid = KernelVariable::new(
			&Kind::uint64_t(),
			&Expr::uint(0).as_kernel_variable_source(&ctx_var),
		);

		let system_call = KernelVariable::new(
			&Kind::uint64_t(),
			&SysEnterField::SyscallNumber
				.as_kernel_schema()
				.as_kernel_variable_source(&ctx_var),
		);

		let pid = KernelVariable::new(
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

		builder.add_kernel_variable(target_pid.clone());
		builder.add_kernel_variable(system_call.clone());
		builder.add_kernel_variable(pid.clone());

		let ctx = builder.build();

		let this_pid = std::process::id();
		let remove_this_pid_op = SelectKernelData::new(
			pid,
			BinaryOperator::Neq,
			Expr::uint(this_pid as u64),
			&ctx,
		)
		.into_op();

		let output_struct = Kind::cstruct(&[
			("timestamp".into(), Kind::uint64_t()),
			("syscall_number".into(), Kind::uint64_t()),
			("pid".into(), Kind::uint64_t()),
		]);

		let mut build_tuple = TupleBuilder::new();
		build_tuple.add_field(
			"timestamp".into(),
			&Kind::uint64_t(),
			&timestamp.variable(),
		);
		let build_tuple = build_tuple.build();
		let var = build_tuple.variable();
		let build_tuple = build_tuple.into_op();

		let output_op = PerfMapBufferAndOutput::new(&ctx, &var).into_op();

		let mut plan = ctx.plan();
		plan.add_op(remove_this_pid_op);
		plan.add_op(build_tuple);
		plan.add_op(output_op);

		let code = plan.emit_code();
		println!("{}", clang_format(&code.as_str()).unwrap());
	}
}
