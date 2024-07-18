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
	Lvalue,
};
use std::{
	sync::Arc,
	collections::HashMap
};

struct KernelPlan {
	ctx: KernelContext,
	plan: Vec<KernelOperator>,
	output: PlanOutput
}

impl KernelPlan {
	fn from_parts(ctx: KernelContext, output: PlanOutput) -> Self {
		KernelPlan { ctx, output, plan: Vec::new() }
	}

	fn add_op(&mut self, op: KernelOperator) {
		self.plan.push(op);
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

	//fn add_append_kernel_data_op(
	//	&mut self,
	//	kernel_data: KernelData,
	//) {
	//	let op = AppendKernelData::new(kernel_data, &self.ctx, &self.output_var).into_op();
	//	self.plan.push(op);
	//}

	fn generate_code(&self) -> CodeGen {

		let mut code = CodeGen::new();

		code.push(Include::FilePath("vmlinux.h".into()).into());
		code.push(Include::Library("bpf/bpf_core_read.h".into()).into());
		code.push(Include::Library("bpf/bpf_helpers.h".into()).into());

		// Define context types
		code.push(self.ctx.ctx_definition());
		code.push(self.output.kind_definition());

		// Build program
		let mut function_builder = self.ctx.program_builder();

		for unit in self.output.variable_definition() {
			function_builder.append_code_unit(unit);
		}

		for op in self.plan.iter() {
			function_builder.append_code_unit(op.execute_op());
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
}

impl KernelOperator {
	pub fn execute_op(&self) -> CodeUnit {
		match self {
			Self::FilterKernelData(x) => x.execute_op(),
			Self::AppendKernelData(x) => x.execute_op(),
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

	fn execute_op(&self) -> CodeUnit {

		let variable = self.kernel_ctx.get_kernel_variable(&self.kernel_data);
		let filter = Expr::binary(variable.expr(), self.op, self.rhs.clone());
		let mut filter_block = ScopeBlock::new();
		filter_block.push(CodeUnit::Return(Expr::uint(0).into()).into());
		IfBlock::from_parts(filter, filter_block).into()
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

	fn execute_op(&self) -> CodeUnit {
		let variable = self.kernel_ctx.get_kernel_variable(&self.kernel_data);
		self.dst.assign(&variable.expr()).into()
	}
}

enum OutputMapType {
	PerfEventArray,
}

struct OutputMap {
	output_t: Kind,
	output_map_t: Kind,
	output_map: Variable,
	output_map_type: OutputMapType,
}

impl OutputMap {
	fn perf_event_map(
		output_t: &Kind,
	) -> Self {
		let output_map_t = Kind::bpf_map(BpfMap::perf_event_array(
					Scalar::cconst("sizeof(int)"),
					Scalar::cconst("sizeof(int)"),
		));
		let output_map = Variable::new(&output_map_t, None);
		Self {
			output_t: output_t.clone(),
			output_map_t,
			output_map,
			output_map_type: OutputMapType::PerfEventArray,
		}
	}
}

struct EventBufferMap {
	event_t: Kind,
	event_buffer_t: Kind,
	buffer_map_t: Kind,
	buffer_map: Variable,
}

impl EventBufferMap {
	fn per_cpu_buffer(event_t: &Kind, size: usize) -> Self {
		let buffer_array_t = Kind::array(event_t, 256);
		let event_buffer_t = Kind::cstruct(
			&[
				("length".into(), Kind::uint32_t()),
				("buffer".into(), buffer_array_t.clone()),
			],
		);
		let buffer_map_t = Kind::bpf_map(BpfMap::per_cpu_array(
				&Kind::__u32(), &event_buffer_t, 1)
		);
		let buffer_map = Variable::new(&buffer_map_t, None);

		Self {
			event_t: event_t.clone(),
			event_buffer_t,
			buffer_map_t,
			buffer_map,
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test() {

		let plan_output = PlanOutput::new(Kind::cstruct(
				&[
				("syscall_number".into(), Kind::uint64_t()),
				("start_time".into(), Kind::uint64_t()),
				],
		));

		let mut kernel_ctx_builder = BpfContext::SyscallEnter.kernel_context_builder();
		kernel_ctx_builder.add_kernel_variable(SysEnterField::SyscallNumber.schema());
		kernel_ctx_builder.add_kernel_variable(CurrentTaskField::Pid.schema());
		let kernel_ctx = kernel_ctx_builder.build();

		let mut plan = KernelPlan::from_parts(kernel_ctx.clone(), plan_output);

		plan.add_filter_kernel_data_op(
			CurrentTaskField::Pid.schema(),
			BinaryOperator::Neq,
			Expr::uint(17),
			&kernel_ctx,
		);

		plan.add_append_kernel_data_op(SysEnterField::SyscallNumber.schema(), "syscall_number");


		let code = plan.generate_code();
		println!("{}", code.generate_code());

		//let result_t: Kind = Kind::cstruct(
		//		&[
		//		("syscall_number".into(), Kind::uint64_t()),
		//		("start_time".into(), Kind::uint64_t()),
		//		],
		//);
		//let result_var = Variable::new(&result_t, None);

		////let buffer_map = EventBufferMap::per_cpu_buffer(&result_t, 256);
		////let output_map = OutputMap::perf_event_map(&buffer_map.event_buffer_t);

		//let sysenter_args_t: Kind = Kind::array(&Kind::uint32_t(), 6);
		//let ctx_t: Kind = Kind::cstruct(
		//		&[
		//		("pad".into(), Kind::uint64_t()),
		//		("syscall_number".into(), Kind::int64_t()),
		//		("args".into(), sysenter_args_t.clone()),
		//		],
		//);

		//// Setup operators
		//let kernel_ctx = KernelContext {
		//	ctx_t: ctx_t.clone(),
		//	result_t: result_t,

		//	working_var,
		//	result_var,

		//	output_map: output_map,
		//	buffer_map: buffer_map,
		//	hook: "foo".into(),
		//	name: "bar".into(),
		//};

		//let assign1 = KernelAppendValue {
		//	lvalue: working_var.lvalue().member("pid"),
		//	expr: Function::with_name("get_task_struct

		//let mut filter_builder = KernelFilterBuilder::new(vec![kernel_ctx.working_t.pointer()]);

		//filter_builder.add_filter(Expr::binary(
		//	filter_builder.func.get_arg(0).unwrap().expr(),
		//	BinaryOperator::Neq,
		//	Expr::uint(19)
		//));

		//let filter = filter_builder.build();

		//let mut kernel_plan = KernelPlan {
		//	ctx: kernel_ctx,
		//	plan: Vec::new(),
		//};
		//kernel_plan.add_op(KernelOperator::Filter(filter));

		//println!("{}", kernel_plan.generate_code().generate_code());
	}
}


//pub struct KernelFilterBuilder {
//	func: FunctionDeclaration,
//	filters: Vec<Expr>,
//}
//
//impl KernelFilterBuilder {
//	fn new(args: Vec<Kind>) -> Self {
//		Self {
//			func: FunctionDeclaration::new(&Kind::bool(), args),
//			filters: Vec::new(),
//		}
//	}
//
//	fn add_filter(&mut self, expr: Expr) {
//		self.filters.push(expr);
//	}
//
//	fn build(mut self) -> KernelFilter {
//		let mut scope_block = ScopeBlock::new();
//
//		for filter in self.filters {
//			let mut filter_block = ScopeBlock::new();
//			filter_block.push(CodeUnit::Return(Expr::bool(false).into()).into());
//			scope_block.push(IfBlock::from_parts(filter, filter_block).into());
//		}
//		scope_block.push(CodeUnit::Return(Expr::bool(true).into()).into());
//		let func = Function::from_optional_parts("filter", Some(self.func), Some(scope_block));
//		KernelFilter { func }
//	}
//}
//
//pub struct KernelFilter {
//	func: Function
//}
//
//impl KernelFilter {
//	fn function_definition(&self) -> Option<CodeUnit> {
//		Some(self.func.definition().into())
//	}
//
//	fn operator_execution(&self, args: Vec<Expr>) -> CodeUnit {
//		let filter_check = Expr::binary(
//			self.func.call(args),
//			BinaryOperator::Eq,
//			Expr::bool(false)
//		);
//		let mut filter_block = ScopeBlock::new();
//		filter_block.push(CodeUnit::Return(Expr::uint(0).into()).into());
//		IfBlock::from_parts(filter_check, filter_block).into()
//	}
//}
//
//pub struct KernelAppendValue {
//	lvalue: Lvalue,
//	expr: Expr,
//}
//
//impl KernelAppendValue {
//	fn function_definition(&self) -> Option<CodeUnit> {
//		None
//	}
//
//	fn operator_execution(&self) -> CodeUnit {
//		self.lvalue.clone().assign(&self.expr).into()
//	}
//}

//enum KernelOperator {
//	Filter(KernelFilter),
//	AppendValue(KernelAppendValue),
//	PerfEventOutput(KernelPerfEventOutput)
//}
//
//impl KernelOperator {
//	fn function_definition(&self) -> Option<CodeUnit> {
//		match self {
//			Self::Filter(x) => x.function_definition(),
//			_ => unimplemented!(),
//		}
//	}
//
//	fn operator_execution(&self, args: Vec<Expr>) -> CodeUnit {
//		match self {
//			Self::Filter(x) => x.operator_execution(args),
//			_ => unimplemented!(),
//		}
//	}
//}

