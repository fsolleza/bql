use rand::prelude::*;
use std::{
	collections::HashMap,
	sync::{
		atomic::{AtomicBool, AtomicU64, Ordering::SeqCst},
		Arc,
	},
};

static VARID: AtomicU64 = AtomicU64::new(0);
static TYPEID: AtomicU64 = AtomicU64::new(0);

/*
 * TODO:
 *  - Attributes (e.g., __attribute) -> SEC macro is a wrapper to attributes
 *  - Member access
 *  - Derefence
 */

#[derive(Clone)]
pub enum Scalar {
	Null,
	Float(f64),
	Uint(u64),
	Bool(bool),
	Int(i64),
	Cstring(String),
	Cconst(String), // catchall for typeof, sizeof, 0 initilize
}

impl Scalar {
	pub fn gen_expression(&self) -> String {
		match self {
			Self::Null => "null".into(),
			Self::Float(x) => format!("{}", x),
			Self::Uint(x) => format!("{}", x),
			Self::Bool(x) => format!("{}", x),
			Self::Int(x) => format!("{}", x),
			Self::Cstring(x) => format!("\"{}\"", x),
			Self::Cconst(x) => format!("{}", x),
		}
	}

	pub fn into_expr(self) -> Expr {
		Expr::scalar(self)
	}

	pub fn cstring(x: &str) -> Self {
		Self::Cstring(x.into())
	}

	pub fn cconst(x: &str) -> Self {
		Self::Cconst(x.into())
	}
}

#[derive(Clone)]
pub struct Kind {
	inner: Arc<InnerKind>,
	defined: Arc<AtomicBool>,
}

impl std::ops::Deref for Kind {
	type Target = InnerKind;
	fn deref(&self) -> &Self::Target {
		&*self.inner
	}
}

impl Kind {
	fn new(k: InnerKind) -> Self {
		let defined = Arc::new(AtomicBool::new(false));
		match k {
			InnerKind::Void => defined.store(true, SeqCst),
			InnerKind::Char => defined.store(true, SeqCst),
			InnerKind::Int => defined.store(true, SeqCst),
			InnerKind::__U32 => defined.store(true, SeqCst),
			InnerKind::Uint32T => defined.store(true, SeqCst),
			InnerKind::Int32T => defined.store(true, SeqCst),
			InnerKind::__U64 => defined.store(true, SeqCst),
			InnerKind::Uint64T => defined.store(true, SeqCst),
			InnerKind::Int64T => defined.store(true, SeqCst),
			InnerKind::SizeT => defined.store(true, SeqCst),
			InnerKind::Bool => defined.store(true, SeqCst),
			InnerKind::Pointer(_) => defined.store(true, SeqCst),
			InnerKind::Struct(_) => {}
			InnerKind::Array(_) => {}
			InnerKind::BpfMap(_) => defined.store(true, SeqCst),
			InnerKind::Other(_) => defined.store(true, SeqCst),
		}

		Self {
			inner: Arc::new(k),
			defined,
		}
	}

	pub fn is_defined(&self) -> bool {
		self.defined.load(SeqCst)
	}

	pub fn void() -> Self {
		Kind::new(InnerKind::Void)
	}
	pub fn int() -> Self {
		Kind::new(InnerKind::Int)
	}
	pub fn char() -> Self {
		Kind::new(InnerKind::Char)
	}
	pub fn __u32() -> Self {
		Kind::new(InnerKind::__U32)
	}
	pub fn __u64() -> Self {
		Kind::new(InnerKind::__U64)
	}
	pub fn uint32_t() -> Self {
		Kind::new(InnerKind::Uint32T)
	}
	pub fn uint64_t() -> Self {
		Kind::new(InnerKind::Uint64T)
	}
	pub fn int32_t() -> Self {
		Kind::new(InnerKind::Int32T)
	}
	pub fn int64_t() -> Self {
		Kind::new(InnerKind::Int64T)
	}
	pub fn size_t() -> Self {
		Kind::new(InnerKind::SizeT)
	}
	pub fn bpf_map(m: BpfMap) -> Self {
		Kind::new(InnerKind::BpfMap(m))
	}
	pub fn other(s: String) -> Self {
		Kind::new(InnerKind::Other(s))
	}
	pub fn bool() -> Self {
		Kind::new(InnerKind::Bool)
	}

	pub fn array(k: &Kind, sz: usize) -> Self {
		Kind::new(InnerKind::Array(Array::new(k, sz)))
	}

	pub fn cstruct(fields: &[(String, Kind)]) -> Self {
		Kind::new(InnerKind::Struct(Struct::new(fields)))
	}

	pub fn pointer(&self) -> Self {
		Kind::new(InnerKind::Pointer(Pointer { typ: self.clone() }))
	}

	pub fn definition(&self) -> KindDefinition {
		KindDefinition { typ: self.clone() }
	}

	pub fn is_pointer(&self) -> bool {
		match &*self.inner {
			InnerKind::Pointer(_) => true,
			_ => false,
		}
	}

	pub fn is_bpf_map(&self) -> bool {
		match &*self.inner {
			InnerKind::BpfMap(_) => true,
			_ => false,
		}
	}

	pub fn is_cstruct(&self) -> bool {
		match &*self.inner {
			InnerKind::Struct(_) => true,
			_ => false,
		}
	}

	pub fn gen_definition(&self) -> String {
		self.defined.store(true, SeqCst);
		self.inner.gen_definition()
	}

	pub fn as_array_ref(&self) -> Option<&Array> {
		match &*self.inner {
			InnerKind::Array(x) => Some(&x),
			_ => None,
		}
	}

	pub fn as_cstruct_ref(&self) -> Option<&Struct> {
		match &*self.inner {
			InnerKind::Struct(x) => Some(&x),
			_ => None,
		}
	}
}

#[derive(Clone)]
pub enum InnerKind {
	Void,
	Int,
	Char,
	Bool,
	__U32,
	__U64,
	Uint32T,
	Uint64T,
	Int32T,
	Int64T,
	SizeT,
	Struct(Struct),
	Array(Array),
	Pointer(Pointer),
	BpfMap(BpfMap),
	Other(String),
}

impl InnerKind {
	pub fn alignment(&self) -> Option<usize> {
		match self {
			Self::Void => None,
			Self::Char => Some(1),
			Self::Bool => Some(1),
			Self::Int => Some(4),
			Self::__U32 => Some(4),
			Self::Uint32T => Some(4),
			Self::Int32T => Some(4),
			Self::__U64 => Some(8),
			Self::Uint64T => Some(8),
			Self::Int64T => Some(8),
			Self::SizeT => Some(8),
			Self::Struct(x) => Some(x.alignment()),
			Self::Array(a) => Some(a.alignment()),
			Self::Pointer(p) => Some(8),
			Self::BpfMap(_) => unimplemented!(),
			Self::Other(_) => unimplemented!(),
		}
	}

	pub fn size(&self) -> Option<usize> {
		match self {
			Self::Void => None,
			Self::Char => Some(1),
			Self::Bool => Some(1),
			Self::Int => Some(4),
			Self::__U32 => Some(4),
			Self::Uint32T => Some(4),
			Self::Int32T => Some(4),
			Self::__U64 => Some(8),
			Self::Uint64T => Some(8),
			Self::Int64T => Some(8),
			Self::SizeT => Some(8),
			Self::Struct(x) => Some(x.size()),
			Self::Array(a) => Some(a.size()),
			Self::Pointer(p) => Some(8),
			Self::BpfMap(_) => unimplemented!(),
			Self::Other(_) => unimplemented!(),
		}
	}

	pub fn gen_signature(&self) -> String {
		match self {
			Self::Int => "int".into(),
			Self::Bool => "bool".into(),
			Self::__U32 => "__u32".into(),
			Self::__U64 => "__u64".into(),
			Self::Uint32T => "uint32_t".into(),
			Self::Uint64T => "uint64_t".into(),
			Self::Int32T => "int32_t".into(),
			Self::Int64T => "int64_t".into(),
			Self::SizeT => "size_t".into(),
			Self::Char => "char".into(),
			Self::Void => "void".into(),
			Self::Struct(s) => s.gen_signature(),
			Self::Array(a) => a.gen_signature(),
			Self::Pointer(p) => p.gen_signature(),
			Self::BpfMap(m) => m.gen_signature(),
			Self::Other(x) => x.clone(),
		}
	}

	pub fn gen_definition(&self) -> String {
		match self {
			Self::Int => "int".into(),
			Self::Bool => "bool".into(),
			Self::Char => "char".into(),
			Self::__U32 => "__u32".into(),
			Self::__U64 => "__u64".into(),
			Self::Uint32T => "uint32_t".into(),
			Self::Uint64T => "uint64_t".into(),
			Self::Int32T => "int32_t".into(),
			Self::Int64T => "int64_t".into(),
			Self::SizeT => "size_t".into(),
			Self::Void => "void".into(),
			Self::Struct(s) => s.gen_definition(),
			Self::Array(a) => a.gen_definition(),
			Self::Pointer(p) => p.gen_definition(),
			Self::BpfMap(m) => m.gen_definition(),
			Self::Other(x) => x.clone(),
		}
	}
}

#[derive(Clone)]
pub struct Pointer {
	typ: Kind,
}

impl Pointer {
	pub fn gen_signature(&self) -> String {
		format!("{} *", self.typ.gen_signature())
	}

	pub fn gen_definition(&self) -> String {
		format!("{} *", self.typ.gen_signature())
	}
}

/// Represents a C expression that returns a value (can return void)
/// For now, we do not allow nested exprs to simplify things. Assign an expr to
/// a variable then send the variable into the expr.
#[derive(Clone)]
pub struct Expr {
	inner: Arc<InnerExpr>,
}

impl Expr {
	pub fn null() -> Self {
		Self {
			inner: Arc::new(InnerExpr::Scalar(Scalar::Null)),
		}
	}
	pub fn float(x: f64) -> Self {
		Self {
			inner: Arc::new(InnerExpr::Scalar(Scalar::Float(x))),
		}
	}
	pub fn uint(x: u64) -> Self {
		Self {
			inner: Arc::new(InnerExpr::Scalar(Scalar::Uint(x))),
		}
	}
	pub fn int(x: i64) -> Self {
		Self {
			inner: Arc::new(InnerExpr::Scalar(Scalar::Int(x))),
		}
	}
	pub fn bool(x: bool) -> Self {
		Self {
			inner: Arc::new(InnerExpr::Scalar(Scalar::Bool(x))),
		}
	}
	pub fn cstring(x: &str) -> Self {
		Self {
			inner: Arc::new(InnerExpr::Scalar(Scalar::Cstring(x.into()))),
		}
	}
	pub fn cconst(x: &str) -> Self {
		Self {
			inner: Arc::new(InnerExpr::Scalar(Scalar::Cconst(x.into()))),
		}
	}

	pub fn scalar(x: Scalar) -> Self {
		Self {
			inner: InnerExpr::Scalar(x).into(),
		}
	}

	pub fn deref(self) -> Self {
		Self {
			inner: InnerExpr::Deref(Deref {
				expr: Box::new(self),
			})
			.into(),
		}
	}

	pub fn cast(self, typ: Kind) -> Self {
		Self {
			inner: InnerExpr::Cast(Cast {
				expr: Box::new(self),
				typ,
			})
			.into(),
		}
	}

	pub fn reference(self) -> Self {
		Self {
			inner: InnerExpr::Reference(Reference::new(Box::new(self))).into(),
		}
	}

	pub fn function_call(x: &Function, args: Vec<Expr>) -> Self {
		Self {
			inner: InnerExpr::FunctionCall(FunctionCall {
				func: x.clone(),
				args,
			})
			.into(),
		}
	}

	pub fn variable(x: &Variable) -> Self {
		Self {
			inner: InnerExpr::Variable(x.clone()).into(),
		}
	}

	pub fn member(self, member: &str) -> Self {
		Self {
			inner: InnerExpr::Member(Member::new(self, member, false)).into(),
		}
	}

	pub fn ref_member(self, member: &str) -> Self {
		Self {
			inner: InnerExpr::Member(Member::new(self, member, true)).into(),
		}
	}

	pub fn binary(l: Expr, op: BinaryOperator, r: Expr) -> Self {
		Self {
			inner: InnerExpr::BinaryExpr(BinaryExpr {
				lr: Box::new((l, r)),
				op,
			})
			.into(),
		}
	}

	pub fn unary(expr: Expr, op: UnaryOperator) -> Self {
		Self {
			inner: InnerExpr::UnaryExpr(UnaryExpr {
				expr: Box::new(expr),
				op,
			})
			.into(),
		}
	}
}

impl std::ops::Deref for Expr {
	type Target = InnerExpr;
	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

pub enum InnerExpr {
	Scalar(Scalar),
	Variable(Variable),
	Member(Member),
	Reference(Reference),
	BinaryExpr(BinaryExpr),
	UnaryExpr(UnaryExpr),
	FunctionCall(FunctionCall),
	Cast(Cast),
	Deref(Deref),
}

impl InnerExpr {
	pub fn gen_expression(&self) -> String {
		match self {
			Self::Scalar(x) => x.gen_expression(),
			Self::Variable(x) => x.gen_expression(),
			Self::Member(x) => x.gen_expression(),
			Self::Reference(x) => x.gen_expression(),
			Self::BinaryExpr(x) => x.gen_expression(),
			Self::FunctionCall(x) => x.gen_expression(),
			Self::UnaryExpr(x) => x.gen_expression(),
			Self::Cast(x) => x.gen_expression(),
			Self::Deref(x) => x.gen_expression(),
		}
	}

	pub fn null() -> Self {
		Self::Scalar(Scalar::Null)
	}
	pub fn float(x: f64) -> Self {
		Self::Scalar(Scalar::Float(x))
	}
	pub fn uint(x: u64) -> Self {
		Self::Scalar(Scalar::Uint(x))
	}
	pub fn int(x: i64) -> Self {
		Self::Scalar(Scalar::Int(x))
	}
	pub fn bool(x: bool) -> Self {
		Self::Scalar(Scalar::Bool(x))
	}
	pub fn cstring(x: &str) -> Self {
		Self::Scalar(Scalar::Cstring(x.into()))
	}
	pub fn cconst(x: &str) -> Self {
		Self::Scalar(Scalar::Cconst(x.into()))
	}

	//pub fn deref(self) -> Self {
	//	Self::Deref( Deref {
	//		expr: Box::new(self),
	//	})
	//}

	//pub fn cast(self, typ: Kind) -> Self {
	//	Self::Cast(Cast { expr: Box::new(self), typ })
	//}

	//pub fn reference(self) -> Self {
	//	Self::Reference(Reference::new(Box::new(self)))
	//}

	//pub fn member(self, member: &str) -> Self {
	//	Self::Member(Member::new(self, member, false))
	//}

	//pub fn ref_member(self, member: &str) -> Self {
	//	Self::Member(Member::new(self, member, true))
	//}

	//pub fn binary(l: Expr, op: BinaryOperator, r: Expr) -> Self {
	//	Self::BinaryExpr(BinaryExpr {
	//		lr: Box::new((l, r)),
	//		op,
	//	})
	//}

	//pub fn unary(expr: Expr, op: UnaryOperator) -> Self {
	//	Self::UnaryExpr(UnaryExpr {
	//		expr: Box::new(expr),
	//		op,
	//	})
	//}

	pub fn gen_code_unit(&self) -> String {
		let mut s = self.gen_expression();
		s.push_str(";\n");
		s
	}
}

pub struct Deref {
	expr: Box<Expr>,
}

impl Deref {
	pub fn new(expr: Box<Expr>) -> Self {
		Deref { expr }
	}

	pub fn gen_expression(&self) -> String {
		format!("*{}", self.expr.gen_expression())
	}
}

pub struct Reference {
	expr: Box<Expr>,
}

impl Reference {
	pub fn new(expr: Box<Expr>) -> Self {
		Reference { expr }
	}

	pub fn gen_expression(&self) -> String {
		format!("&({})", self.expr.gen_expression())
	}
}

pub struct Cast {
	expr: Box<Expr>,
	typ: Kind,
}

impl Cast {
	pub fn gen_expression(&self) -> String {
		format!(
			"(({}){})",
			self.typ.gen_signature(),
			self.expr.gen_expression()
		)
	}
}

pub struct Member {
	expr: Box<Expr>,
	member: String,
	is_ref: bool,
}

impl Member {
	pub fn new(expr: Expr, member: &str, is_ref: bool) -> Self {
		Member {
			expr: Box::new(expr),
			member: member.into(),
			is_ref,
		}
	}

	pub fn gen_expression(&self) -> String {
		if self.is_ref {
			format!("{}->{}", self.expr.gen_expression(), self.member)
		} else {
			format!("{}.{}", self.expr.gen_expression(), self.member)
		}
	}
}

#[derive(Copy, Clone)]
pub enum BinaryOperator {
	Add,
	Sub,
	Eq,
	Neq,
	Lt,
	And,
	Or,
}

impl BinaryOperator {
	fn gen_symbol(&self) -> String {
		match self {
			Self::Add => "+".into(),
			Self::Sub => "-".into(),
			Self::Eq => "==".into(),
			Self::Lt => "<".into(),
			Self::Neq => "!=".into(),
			Self::And => "&&".into(),
			Self::Or => "||".into(),
		}
	}
}

pub struct BinaryExpr {
	lr: Box<(Expr, Expr)>,
	op: BinaryOperator,
}

impl BinaryExpr {
	pub fn gen_expression(&self) -> String {
		let mut s = String::new();
		format!(
			"({}) {} ({})",
			self.lr.0.gen_expression(),
			self.op.gen_symbol(),
			self.lr.1.gen_expression()
		)
	}
}

pub enum UnaryOperator {
	Not,
}

impl UnaryOperator {
	fn gen_symbol(&self) -> String {
		match self {
			Self::Not => "!".into(),
		}
	}
}

pub struct UnaryExpr {
	expr: Box<Expr>,
	op: UnaryOperator,
}

impl UnaryExpr {
	pub fn gen_expression(&self) -> String {
		let mut s = String::new();
		format!("{}({})", self.op.gen_symbol(), self.expr.gen_expression())
	}
}

pub struct FunctionCall {
	func: Function,
	args: Vec<Expr>,
}

impl FunctionCall {
	pub fn gen_expression(&self) -> String {
		self.func.gen_call(&self.args)
	}
}

pub struct FunctionDefinition {
	func: Function,
}

impl FunctionDefinition {
	pub fn gen_code_unit(&self) -> String {
		self.func.gen_definition().unwrap()
	}
}

pub struct BpfProgramDefinition {
	bpf: BpfProgram,
}

impl BpfProgramDefinition {
	pub fn gen_code_unit(&self) -> String {
		self.bpf.gen_definition()
	}
}

impl Into<BpfProgramDefinition> for &BpfProgram {
	fn into(self) -> BpfProgramDefinition {
		BpfProgramDefinition { bpf: self.clone() }
	}
}

pub enum CodeUnit {
	Include(Include),
	KindDefinition(KindDefinition),
	FunctionDefinition(FunctionDefinition),
	VariableDefinition(VariableDefinition),
	LvalueAssignment(LvalueAssignment),
	Expr(Expr),
	If(IfBlock),
	ScopeBlock(ScopeBlock),
	BpfLicense,
	BpfProgramDefinition(BpfProgramDefinition),
	Return(Expr),
}

impl CodeUnit {
	pub fn gen_code_unit(&self) -> String {
		match self {
			Self::KindDefinition(x) => x.gen_code_unit(),
			Self::VariableDefinition(x) => x.gen_code_unit(),
			Self::FunctionDefinition(x) => x.gen_code_unit(),
			Self::Expr(x) => x.gen_code_unit(),
			Self::If(x) => x.gen_code_unit(),
			Self::Include(x) => x.gen_code_unit(),
			Self::ScopeBlock(x) => x.gen_code_unit(),
			Self::BpfProgramDefinition(x) => x.gen_code_unit(),
			Self::LvalueAssignment(x) => x.gen_code_unit(),
			Self::Return(x) => {
				format!("return {};\n", x.gen_expression())
			}
			Self::BpfLicense => {
				format!(
					"{};\n",
					r#"char LICENSE[] SEC("license") = "Dual BSD/GPL""#
				)
			}
		}
	}
}

impl Into<CodeUnit> for BpfProgramDefinition {
	fn into(self) -> CodeUnit {
		CodeUnit::BpfProgramDefinition(self)
	}
}

impl Into<CodeUnit> for Include {
	fn into(self) -> CodeUnit {
		CodeUnit::Include(self)
	}
}

impl Into<CodeUnit> for VariableDefinition {
	fn into(self) -> CodeUnit {
		CodeUnit::VariableDefinition(self)
	}
}

impl Into<CodeUnit> for KindDefinition {
	fn into(self) -> CodeUnit {
		CodeUnit::KindDefinition(self)
	}
}

impl Into<CodeUnit> for FunctionDefinition {
	fn into(self) -> CodeUnit {
		CodeUnit::FunctionDefinition(self)
	}
}

impl Into<CodeUnit> for Expr {
	fn into(self) -> CodeUnit {
		CodeUnit::Expr(self)
	}
}

impl Into<CodeUnit> for IfBlock {
	fn into(self) -> CodeUnit {
		CodeUnit::If(self)
	}
}

impl Into<CodeUnit> for LvalueAssignment {
	fn into(self) -> CodeUnit {
		CodeUnit::LvalueAssignment(self)
	}
}

pub enum Include {
	FilePath(String),
	Library(String),
}

impl Include {
	pub fn gen_code_unit(&self) -> String {
		match self {
			Self::FilePath(x) => format!("#include \"{}\"\n", x),
			Self::Library(x) => format!("#include <{}>\n", x),
		}
	}
}

pub struct KindDefinition {
	typ: Kind,
}

impl KindDefinition {
	fn gen_code_unit(&self) -> String {
		let mut s = self.typ.gen_definition();
		s.push_str(";\n");
		self.typ.defined.store(true, SeqCst);
		s
	}
}

pub struct VariableDefinition {
	var: Variable,
}

impl VariableDefinition {
	fn gen_code_unit(&self) -> String {
		let mut s = self.var.gen_definition();
		s.push_str(";\n");
		s
	}
}

pub struct IfBlock {
	expr: Expr,
	block: ScopeBlock,
}

impl IfBlock {
	pub fn from_parts(expr: Expr, block: ScopeBlock) -> Self {
		Self { expr, block }
	}

	pub fn gen_code_unit(&self) -> String {
		format!(
			"if ({})\n{}",
			self.expr.gen_expression(),
			self.block.gen_code_block()
		)
	}
}

pub struct ScopeBlock {
	units: Vec<CodeUnit>,
}

impl ScopeBlock {
	pub fn new() -> Self {
		ScopeBlock { units: Vec::new() }
	}

	pub fn push(&mut self, unit: CodeUnit) {
		self.units.push(unit);
	}

	pub fn gen_code_block(&self) -> String {
		let mut s: String = "{\n".into();
		for unit in &self.units {
			s.push('\t');
			s.push_str(&unit.gen_code_unit());
		}
		s.push_str("}\n");
		s
	}

	pub fn gen_code_unit(&self) -> String {
		self.gen_code_block()
	}
}

#[derive(Clone)]
pub struct FunctionDeclaration {
	inner: Arc<InnerFunctionDeclaration>,
}

impl FunctionDeclaration {
	pub fn new(return_type: &Kind, argument_types: Vec<Kind>) -> Self {
		let inner = InnerFunctionDeclaration::new(return_type, argument_types);
		Self {
			inner: inner.into(),
		}
	}

	pub fn get_arg(&self, idx: usize) -> Option<Variable> {
		self.inner.get_arg(idx)
	}

	pub fn arg_types(&self) -> &[Kind] {
		&self.inner.arg_types
	}

	pub fn arg_vars(&self) -> &[Variable] {
		&self.inner.arg_vars
	}

	pub fn ret_kind(&self) -> &Kind {
		&self.inner.ret
	}
}

pub struct InnerFunctionDeclaration {
	ret: Kind,
	arg_types: Vec<Kind>,
	arg_vars: Vec<Variable>,
}

impl InnerFunctionDeclaration {
	pub fn new(return_type: &Kind, argument_types: Vec<Kind>) -> Self {
		let arg_vars: Vec<Variable> = argument_types
			.iter()
			.cloned()
			.map(|x| Variable::new(&x, None).into())
			.collect();

		Self {
			ret: return_type.clone(),
			arg_types: argument_types,
			arg_vars,
		}
	}

	pub fn get_arg(&self, idx: usize) -> Option<Variable> {
		Some(self.arg_vars.get(idx)?.clone())
	}
}

pub struct FunctionBuilder {
	name: String,
	declaration: FunctionDeclaration,
	scope_block: ScopeBlock,
}

impl FunctionBuilder {
	pub fn new(name: &str, declaration: &FunctionDeclaration) -> Self {
		Self {
			name: name.into(),
			declaration: declaration.clone(),
			scope_block: ScopeBlock::new(),
		}
	}

	pub fn append_code_unit(&mut self, code_unit: CodeUnit) {
		self.scope_block.push(code_unit);
	}

	pub fn build(self) -> Function {
		Function::from_optional_parts(
			self.name.as_str(),
			Some(self.declaration),
			Some(self.scope_block),
		)
	}
}

#[derive(Clone)]
pub struct Function {
	inner: Arc<InnerFunction>,
}

impl std::ops::Deref for Function {
	type Target = InnerFunction;
	fn deref(&self) -> &Self::Target {
		&*self.inner
	}
}

impl Function {
	pub fn with_name(name: &str) -> Self {
		Self::from_optional_parts(name, None, None)
	}

	pub fn from_optional_parts(
		name: &str,
		declaration: Option<FunctionDeclaration>,
		definition: Option<ScopeBlock>,
	) -> Self {
		Self {
			inner: Arc::new(InnerFunction {
				name: name.into(),
				declaration,
				definition,
			}),
		}
	}

	pub fn new_from_required_parts(
		name: &str,
		decl: FunctionDeclaration,
		def: ScopeBlock,
	) -> Self {
		Self::from_optional_parts(name, Some(decl), Some(def))
	}

	pub fn definition(&self) -> FunctionDefinition {
		FunctionDefinition { func: self.clone() }
	}

	pub fn call(&self, args: Vec<Expr>) -> Expr {
		Expr::function_call(self, args)
	}
}

pub struct InnerFunction {
	name: String,
	declaration: Option<FunctionDeclaration>,
	definition: Option<ScopeBlock>,
}

impl InnerFunction {
	pub fn get_arg(&self, idx: usize) -> Option<Variable> {
		self.declaration.as_ref()?.get_arg(idx)
	}

	pub fn gen_declaration(&self) -> Option<String> {
		let decl = self.declaration.as_ref()?;
		let mut preamble = String::new();
		for arg in decl.arg_types() {
			if !arg.is_defined() {
				preamble.push_str(&format!("{};\n", arg.gen_definition()));
			}
		}

		let mut args = String::new();

		for (i, arg) in decl.arg_vars().iter().enumerate() {
			args.push_str(&arg.gen_definition());
			//args.push_str(&format!(" arg_{}", i));
			if i < decl.arg_vars().len() - 1 {
				args.push_str(", ");
			}
		}
		Some(format!(
			"{}{} {}({})",
			preamble,
			decl.ret_kind().gen_signature(),
			&self.name,
			args
		))
	}

	pub fn gen_definition(&self) -> Option<String> {
		let defn = self.definition.as_ref()?;
		Some(format!(
			"{} {}",
			self.gen_declaration()?,
			defn.gen_code_block()
		))
	}

	pub fn gen_call(&self, args: &[Expr]) -> String {
		let mut s = format!("{}(", self.name);

		for (i, arg) in args.iter().enumerate() {
			s.push_str(&format!("{}", arg.gen_expression()));
			if i < args.len() - 1 {
				s.push(',');
			}
		}

		s.push(')');
		s
	}
}

#[derive(Copy, Clone)]
pub enum Qualifier {
	Const,
	Volatile,
}

impl Into<String> for Qualifier {
	fn into(self) -> String {
		match self {
			Self::Const => "const".into(),
			Self::Volatile => "volatile".into(),
		}
	}
}

#[derive(Clone)]
pub struct Variable {
	inner: Arc<InnerVariable>,
}

impl std::ops::Deref for Variable {
	type Target = InnerVariable;
	fn deref(&self) -> &Self::Target {
		&*self.inner
	}
}

impl Variable {
	pub fn new(typ: &Kind, qualifiers: Option<&[Qualifier]>) -> Self {
		let id = VARID.fetch_add(1, SeqCst);
		Self::new_with_id(typ, qualifiers, id)
	}

	pub fn new_with_id(
		typ: &Kind,
		qualifiers: Option<&[Qualifier]>,
		id: u64,
	) -> Self {
		Self {
			inner: Arc::new(InnerVariable {
				typ: typ.clone(),
				id,
				qualifiers: {
					match qualifiers {
						None => None,
						Some(x) => Some(x.into()),
					}
				},
			}),
		}
	}

	pub fn definition(&self) -> VariableDefinition {
		VariableDefinition { var: self.clone() }
	}

	pub fn lvalue(&self) -> Lvalue {
		Lvalue::variable(self)
	}

	pub fn expr(&self) -> Expr {
		Expr::variable(self)
	}

	pub fn name(&self) -> String {
		self.inner.name()
	}
}

pub struct InnerVariable {
	pub typ: Kind,
	pub qualifiers: Option<Vec<Qualifier>>,
	id: u64,
}

impl InnerVariable {
	fn name(&self) -> String {
		format!("var_{}", self.id)
	}

	fn gen_definition(&self) -> String {
		let mut string_qualifiers = String::new();
		if let Some(qualifiers) = self.qualifiers.as_ref() {
			for i in qualifiers.as_slice() {
				let i: String = (*i).into();
				string_qualifiers.push_str(&format!("{} ", i));
			}
		}
		let mut s = format!(
			"{}{} var_{}",
			string_qualifiers,
			self.typ.gen_signature(),
			self.id
		);
		if self.typ.is_bpf_map() {
			s.push_str(" SEC(\".maps\")");
		} else if self.typ.is_cstruct() {
			// Zero initialize the struct
			s.push_str(" = {0}");
		}
		s
	}

	fn gen_expression(&self) -> String {
		format!("var_{}", self.id)
	}
}

#[derive(Clone)]
pub struct Array {
	typ: Kind,
	sz: usize,
	id: u64,
}

impl Array {
	pub fn alignment(&self) -> usize {
		self.typ.alignment().unwrap()
	}

	pub fn len(&self) -> usize {
		self.sz
	}

	pub fn size(&self) -> usize {
		self.sz * self.typ.size().unwrap()
	}

	pub fn new(typ: &Kind, sz: usize) -> Self {
		let id = TYPEID.fetch_add(1, SeqCst);
		Self::new_with_id(typ, sz, id)
	}

	pub fn new_with_id(typ: &Kind, sz: usize, id: u64) -> Self {
		Self {
			typ: typ.clone(),
			sz,
			id,
		}
	}

	pub fn gen_signature(&self) -> String {
		format!("ArrKind_{}", self.id)
	}

	pub fn gen_definition(&self) -> String {
		let mut s: String = "".into();

		if !self.typ.is_defined() {
			s.push_str(&format!("{};\n", self.typ.gen_definition()));
		}

		s.push_str(&format!(
			"typedef {} ArrKind_{}[{}]",
			self.typ.gen_signature(),
			self.id,
			self.sz
		));
		s
	}
}

#[derive(Clone)]
pub struct Struct {
	fields: Vec<(String, Kind)>,
	offsets: HashMap<String, usize>,
	alignment: usize,
	size: usize,
	id: u64,
}

impl Struct {
	pub fn offsetof(&self, field: &String) -> Option<usize> {
		self.offsets.get(field).copied()
	}

	pub fn alignment(&self) -> usize {
		self.alignment
	}

	pub fn size(&self) -> usize {
		self.size
	}

	pub fn new(fields: &[(String, Kind)]) -> Self {
		Self::new_with_id(fields, TYPEID.fetch_add(1, SeqCst))
	}

	pub fn read_fields<'a, 'b>(
		&'a self,
		b: &'b [u8],
	) -> Vec<(&'a str, &'b [u8])> {
		let mut result = Vec::new();
		for (f, _) in self.fields.iter() {
			let bytes = self.read(f, b).unwrap();
			result.push((f.as_str(), bytes));
		}
		result
	}

	pub fn read<'a>(
		&self,
		field: &String,
		bytes: &'a [u8],
	) -> Option<&'a [u8]> {
		let offset = self.offsetof(field)?;
		let mut sz = 0;
		for (f, k) in self.fields.iter() {
			if f == field {
				sz = k.size().unwrap() as usize;
				break;
			}
		}
		Some(&bytes[offset..offset + sz])
	}

	pub fn new_with_id(fields: &[(String, Kind)], id: u64) -> Self {
		// Calculate offsets
		let mut offsets = HashMap::new();
		let mut align = 0;
		let mut off = 0;
		for (m, k) in fields.iter() {
			let a = k.alignment().unwrap();

			// move the offset to proper alignment if necessary
			let pad = off % a;
			if pad > 0 {
				off += a - pad;
			}
			offsets.insert(m.clone(), off);

			// move offset by size of the type
			off += k.size().unwrap();

			// the alignment of the struct is the same as the max alignment of
			// each of its types
			align = align.max(a);
		}

		// The size of the struct (currently the value off), should include
		// padding to alignment
		let pad = off % align;
		if pad > 0 {
			off += align - pad;
		}

		Self {
			fields: fields.into(),
			size: off,
			alignment: align,
			offsets,
			id,
		}
	}

	pub fn gen_signature(&self) -> String {
		format!("struct_{}", self.id)
	}

	pub fn gen_definition(&self) -> String {
		let mut s: String = "".into();
		for (_, typ) in &self.fields {
			if !typ.is_defined() {
				s.push_str(&format!("{};\n", typ.gen_definition()));
			}
		}

		s.push_str("typedef struct {\n");

		for (name, typ) in &self.fields {
			s.push_str(&format!("\t{} {};\n", typ.gen_signature(), name));
		}

		s.push_str(&format!("}} struct_{}", self.id));
		s
	}
}

#[derive(Clone)]
pub enum BpfMap {
	PerfEventArray(PerfEventArray),
	PerCpuArray(PerCpuArray),
}

impl BpfMap {
	pub fn gen_signature(&self) -> String {
		match self {
			Self::PerfEventArray(x) => x.gen_signature(),
			Self::PerCpuArray(x) => x.gen_signature(),
		}
	}

	pub fn gen_definition(&self) -> String {
		match self {
			Self::PerfEventArray(x) => x.gen_definition(),
			Self::PerCpuArray(x) => x.gen_definition(),
		}
	}

	pub fn per_cpu_array(key: &Kind, value: &Kind, max_entries: u64) -> Self {
		Self::PerCpuArray(PerCpuArray::new(key, value, max_entries))
	}

	pub fn perf_event_array(key_size: Scalar, value_size: Scalar) -> Self {
		Self::PerfEventArray(PerfEventArray::new(key_size, value_size))
	}
}

impl Into<BpfMap> for PerfEventArray {
	fn into(self) -> BpfMap {
		BpfMap::PerfEventArray(self)
	}
}

impl Into<BpfMap> for PerCpuArray {
	fn into(self) -> BpfMap {
		BpfMap::PerCpuArray(self)
	}
}

#[derive(Clone)]
pub struct PerCpuArray {
	key: Kind,
	value: Kind,
	max_entries: u64,
	id: u64,
}

impl PerCpuArray {
	pub fn new_with_id(
		key: &Kind,
		value: &Kind,
		max_entries: u64,
		id: u64,
	) -> Self {
		Self {
			key: key.clone(),
			value: value.clone(),
			max_entries,
			id,
		}
	}

	pub fn new(key: &Kind, value: &Kind, max_entries: u64) -> Self {
		Self::new_with_id(key, value, max_entries, TYPEID.fetch_add(1, SeqCst))
	}

	pub fn gen_signature(&self) -> String {
		format!("per_cpu_array_t_{}", self.id)
	}

	pub fn gen_definition(&self) -> String {
		let mut s: String = "".into();

		if !self.key.is_defined() {
			s.push_str(&self.key.gen_definition());
			s.push_str(";\n");
		}

		if !self.value.is_defined() {
			s.push_str(&self.value.gen_definition());
			s.push_str(";\n");
		}

		s.push_str("typedef struct {\n");
		s.push_str("__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);\n");

		let k = format!("__type(key, {});\n", self.key.gen_signature());
		let v = format!("__type(value, {});\n", self.value.gen_signature());
		let e = format!("__uint(max_entries, {});\n", self.max_entries);
		s.push_str(&k);
		s.push_str(&v);
		s.push_str(&e);

		let map_type = format!("per_cpu_array_t_{}", self.id);
		s.push_str(&format!("}} {}", map_type));
		s
	}
}

#[derive(Clone)]
pub struct PerfEventArray {
	key_size: Scalar,
	value_size: Scalar,
	id: u64,
}

impl PerfEventArray {
	pub fn new_with_id(key_size: Scalar, value_size: Scalar, id: u64) -> Self {
		Self {
			key_size,
			value_size,
			id,
		}
	}

	pub fn new(key_size: Scalar, value_size: Scalar) -> Self {
		Self::new_with_id(key_size, value_size, TYPEID.fetch_add(1, SeqCst))
	}

	pub fn gen_signature(&self) -> String {
		format!("perf_event_array_t_{}", self.id)
	}

	pub fn gen_definition(&self) -> String {
		let map_type = self.gen_signature();
		let mut s: String = "typedef struct {\n".into();
		let k =
			format!("__uint(key_size, {});\n", self.key_size.gen_expression());
		let v = format!(
			"__uint(value_size, {});\n",
			self.value_size.gen_expression()
		);
		s.push_str("__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);\n");
		s.push_str(&k);
		s.push_str(&v);
		s.push_str(&format!("}} {}", map_type));
		s
	}
}

struct InnerBpfProgram {
	func: Function,
	hook: String,
}

#[derive(Clone)]
pub struct BpfProgram {
	inner: Arc<InnerBpfProgram>,
}

impl BpfProgram {
	pub fn from_function(func: Function, hook: &str) -> Self {
		Self {
			inner: InnerBpfProgram {
				func,
				hook: hook.into(),
			}
			.into(),
		}
	}

	pub fn new(
		func_name: &str,
		decl: FunctionDeclaration,
		def: ScopeBlock,
		hook: &str,
	) -> Self {
		let func = Function::new_from_required_parts(func_name, decl, def);
		Self::from_function(func, hook)
	}

	pub fn definition(&self) -> BpfProgramDefinition {
		BpfProgramDefinition { bpf: self.clone() }
	}

	pub fn gen_definition(&self) -> String {
		format!(
			"SEC(\"{}\")\n{}",
			self.inner.hook,
			self.inner.func.gen_definition().unwrap()
		)
	}

	pub fn get_arg(&self, idx: usize) -> Variable {
		self.inner.func.get_arg(idx).unwrap()
	}
}

#[derive(Clone)]
pub struct Lvalue {
	inner: Arc<InnerLvalue>,
}

impl Lvalue {
	pub fn member(self, member: &str) -> Self {
		let inner = InnerLvalue::Member(LvalueMember {
			parent: Box::new(self),
			member: member.into(),
			is_ref: false,
		});
		Self {
			inner: inner.into(),
		}
	}

	pub fn ref_member(self, member: &str) -> Self {
		let inner = InnerLvalue::Member(LvalueMember {
			parent: Box::new(self),
			member: member.into(),
			is_ref: true,
		});
		Self {
			inner: inner.into(),
		}
	}

	pub fn offset(self, idx: Expr) -> Self {
		let inner = InnerLvalue::Offset(LvalueOffset {
			parent: Box::new(self),
			idx,
		});
		Self {
			inner: inner.into(),
		}
	}

	pub fn gen_expression(&self) -> String {
		match &*self.inner {
			InnerLvalue::Variable(x) => x.gen_expression(),
			InnerLvalue::Member(x) => format!("{}", x.gen_expression()),
			InnerLvalue::Offset(x) => format!("{}", x.gen_expression()),
		}
	}

	pub fn assign(&self, expr: &Expr) -> LvalueAssignment {
		LvalueAssignment {
			lvalue: self.clone(),
			op: LvalueAssignmentOperator::Assign,
			expr: expr.clone(),
			deref: false,
		}
	}

	pub fn add_assign(&self, expr: Expr) -> LvalueAssignment {
		LvalueAssignment {
			lvalue: self.clone(),
			op: LvalueAssignmentOperator::AddAssign,
			expr,
			deref: false,
		}
	}

	pub fn variable(x: &Variable) -> Self {
		let inner = InnerLvalue::Variable(x.clone());
		Self {
			inner: inner.into(),
		}
	}
}

pub enum InnerLvalue {
	Variable(Variable),
	Member(LvalueMember),
	Offset(LvalueOffset),
}

//impl InnerLvalue {
//	pub fn member(self, member: &str) -> Self {
//		Lvalue::Member(LvalueMember {
//			parent: Box::new(self),
//			member: member.into(),
//			is_ref: false,
//		})
//	}
//
//	pub fn ref_member(self, member: &str) -> Self {
//		Lvalue::Member(LvalueMember {
//			parent: Box::new(self),
//			member: member.into(),
//			is_ref: true,
//		})
//	}
//
//	pub fn offset(self, idx: Expr) -> Self {
//		Lvalue::Offset(LvalueOffset { parent: Box::new(self), idx })
//	}
//
//	pub fn gen_expression(&self) -> String {
//		match self {
//			Self::Variable(x) => x.gen_expression(),
//			Self::Member(x) => format!("{}", x.gen_expression()),
//			Self::Offset(x) => format!("{}", x.gen_expression()),
//		}
//	}
//
//	pub fn assign(self, expr: &Expr) -> LvalueAssignment {
//		LvalueAssignment {
//			lvalue: self,
//			op: LvalueAssignmentOperator::Assign,
//			expr: expr.clone(),
//			deref: false,
//		}
//	}
//
//	pub fn add_assign(self, expr: Expr) -> LvalueAssignment {
//		LvalueAssignment {
//			lvalue: self,
//			op: LvalueAssignmentOperator::AddAssign,
//			expr,
//			deref: false,
//		}
//	}
//}

pub struct LvalueOffset {
	parent: Box<Lvalue>,
	idx: Expr,
}

impl LvalueOffset {
	pub fn gen_expression(&self) -> String {
		format!(
			"{}[{}]",
			self.parent.gen_expression(),
			self.idx.gen_expression()
		)
	}
}

pub struct LvalueMember {
	parent: Box<Lvalue>,
	member: String,
	is_ref: bool,
}

impl LvalueMember {
	pub fn gen_expression(&self) -> String {
		if self.is_ref {
			format!("{}->{}", self.parent.gen_expression(), self.member)
		} else {
			format!("{}.{}", self.parent.gen_expression(), self.member)
		}
	}
}

pub enum LvalueAssignmentOperator {
	Assign,
	AddAssign,
}

impl LvalueAssignmentOperator {
	pub fn gen_symbol(&self) -> String {
		match self {
			Self::Assign => "=".into(),
			Self::AddAssign => "+=".into(),
		}
	}
}

pub struct LvalueAssignment {
	lvalue: Lvalue,
	op: LvalueAssignmentOperator,
	expr: Expr,
	deref: bool,
}

impl LvalueAssignment {
	pub fn is_deref(mut self) -> Self {
		self.deref = true;
		self
	}

	pub fn gen_code_unit(&self) -> String {
		if self.deref {
			format!(
				"*{} {} {};\n",
				self.lvalue.gen_expression(),
				self.op.gen_symbol(),
				self.expr.gen_expression()
			)
		} else {
			format!(
				"{} {} {};\n",
				self.lvalue.gen_expression(),
				self.op.gen_symbol(),
				self.expr.gen_expression()
			)
		}
	}
}

pub struct CodeGen {
	units: Vec<CodeUnit>,
}

impl CodeGen {
	pub fn emit_code(&self) -> String {
		let mut s = String::new();
		for unit in &self.units {
			s.push_str(&unit.gen_code_unit());
		}
		s
	}

	pub fn push(&mut self, unit: CodeUnit) {
		self.units.push(unit);
	}

	pub fn new() -> Self {
		Self { units: Vec::new() }
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use clang_format::clang_format;

	fn remove_whitespace(s: &str) -> String {
		s.chars().filter(|c| !c.is_whitespace()).collect()
	}

	fn assert_code_eq(l: &str, r: &str) {
		assert_eq!(remove_whitespace(l), remove_whitespace(r));
	}

	#[test]
	fn test_program_gen() {
		let exp = r#"{
			#include "vmlinux.h"
			#include <bpf/bpf_core_read.h>
			#include <bpf/bpf_helpers.h>

			const volatile uint32_t var_0;
			const volatile uint32_t var_1;

			var_0 = 12345;
			var_1 = 67890;

			typedef uint32_t ArrKind_0[6];

			typedef struct struct_0 {
				uint64_t pad;
				int64_t syscall_number;
				ArrKind_0 args;
			} struct_0;

			typedef struct struct_1 {
				uint32_t pid;
				uint32_t tid;
				uint64_t syscall_number;
				uint64_t start_time;
				uint64_t duration;
			} struct_1;

			typedef struct_1 ArrKind_2[256];

			typedef struct struct_2  {
				uint32_t length;
				ArrKind_2 buffer;
			} struct_2;

			typedef struct perf_event_array_t_0 {
				__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
				__uint(key_size, sizeof(int));
				__uint(value_size, sizeof(int));
			} perf_event_array_t_0;
			perf_event_array_t_0 var_0 SEC(".maps");

			typedef struct per_cpu_array_t_0 {
				__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
				__type(key, __u32);
				__type(value, struct_2);
				__max_entries(max_entries, 1);
			} per_cpu_array_t_0;

			per_cpu_array_t_0 var_1 SEC(".maps");

		}"#;

		let mut code_block = CodeGen::new();
		code_block.push(Include::FilePath("vmlinux.h".into()).into());
		code_block.push(Include::Library("bpf/bpf_core_read.h".into()).into());
		code_block.push(Include::Library("bpf/bpf_helpers.h".into()).into());

		/*
		 * My Pid variable declaration and definition
		 */
		let qualifiers = &[Qualifier::Const, Qualifier::Volatile];
		let my_pid = Variable::new(&Kind::uint32_t(), Some(qualifiers));
		let def = my_pid.definition();

		let value = Expr::uint(12345);
		let assign = Lvalue::variable(&my_pid).assign(&value);
		code_block.push(def.into());
		code_block.push(assign.into());

		/*
		 * Target PID variable declaration and definition
		 */
		let q = &[Qualifier::Const, Qualifier::Volatile];
		let target_pid = Variable::new(&Kind::uint32_t(), Some(q));
		let def = target_pid.definition();

		let value = Expr::uint(67890);
		let assign = Lvalue::variable(&target_pid).assign(&value);

		code_block.push(def.into());
		code_block.push(assign.into());

		/*
		 * Argument array in the sysenter BPF hook context
		 */
		let sysenter_args_t: Kind = Kind::array(&Kind::uint32_t(), 6);
		//let def: KindDefinition = sysenter_args_t.definition();
		//code_block.push(def.into());

		/*
		 * Struct 0: BPF ctx
		 */
		let sys_enter_ctx: Kind = Kind::cstruct(&[
			("pad".into(), Kind::uint64_t()),
			("syscall_number".into(), Kind::int64_t()),
			("args".into(), sysenter_args_t.clone()),
		]);
		let def = sys_enter_ctx.definition();
		code_block.push(def.into());

		/*
		 * Struct 1: Syscall Event
		 */
		let syscall_event_t: Kind = Kind::cstruct(&[
			("pid".into(), Kind::uint32_t()),
			("tid".into(), Kind::uint32_t()),
			("syscall_number".into(), Kind::uint64_t()),
			("start_time".into(), Kind::uint64_t()),
			("duration".into(), Kind::uint64_t()),
		]);
		let def = syscall_event_t.definition();
		code_block.push(def.into());

		/*
		 * Array 1: Array used in the event buffer (struct 2)
		 */
		let buffer_array_t = Kind::array(&syscall_event_t, 256);
		let def = buffer_array_t.definition();
		code_block.push(def.into());

		/*
		 * Struct 2: A buffer of such syscall events
		 */
		let event_buffer_t = Kind::cstruct(&[
			("length".into(), Kind::uint32_t()),
			("buffer".into(), buffer_array_t.clone()),
		]);
		let def = event_buffer_t.definition();
		code_block.push(def.into());

		/*
		 * Perf Event Array to send event buffers to user space
		 */
		let event_buffer_map_t =
			Kind::bpf_map(BpfMap::PerfEventArray(PerfEventArray::new(
				Scalar::cconst("sizeof(int)"),
				Scalar::cconst("sizeof(int)"),
			)));
		let def = event_buffer_map_t.definition();
		code_block.push(def.into());

		/*
		 * Define the actual perf event array map for event buffers
		 */
		let event_buffer_map = Variable::new(&event_buffer_map_t, None);
		let def: VariableDefinition = event_buffer_map.definition();
		code_block.push(def.into());

		/*
		 * Kinddef the syscall buffer map
		 */
		let syscall_buffer_map_t = Kind::bpf_map(BpfMap::PerCpuArray(
			PerCpuArray::new(&Kind::__u32(), &event_buffer_t, 1),
		));
		let def = syscall_buffer_map_t.definition();
		code_block.push(def.into());

		/*
		 * Define the syscall buffer map object
		 */
		let syscall_buffer_map = Variable::new(&syscall_buffer_map_t, None);
		let def = syscall_buffer_map.definition();
		code_block.push(def.into());

		/*
		 * Define a few functions we will use
		 */
		let sizeof = Function::with_name("sizeof");
		let bpf_probe_read = Function::with_name("bpf_probe_read");
		let bpf_ktime_get_ns = Function::with_name("bpf_ktime_get_ns");
		let bpf_map_lookup_elem = Function::with_name("bpf_map_lookup_elem");
		let bpf_perf_event_output =
			Function::with_name("bpf_perf_event_output");

		/*
		 * Function declaration for BPF program
		 */
		let ret: Kind = Kind::int();
		let args: Vec<Kind> = vec![sys_enter_ctx.pointer()];
		let bpf_declaration = FunctionDeclaration::new(&ret, args);

		/*
		 * Begin building the scope block for the function
		 */
		let mut bpf_scope_block = ScopeBlock::new();

		/*
		 * Get task struct into a variable
		 */
		let task_struct_t = Kind::other("struct task_struct".into());
		let task_struct_ptr_t = task_struct_t.pointer();

		let task = Variable::new(&task_struct_ptr_t, None);
		let def = task.definition();

		let bpf_get_current_task = Function::with_name("bpf_get_current_task");

		let expr = bpf_get_current_task.call(Vec::new());

		let assign = task.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Initialize a variable to hold the pid
		 */
		let pid = Variable::new(&Kind::uint32_t(), None);

		let def = pid.definition();
		let assign = pid.lvalue().assign(&Expr::uint(0));

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * And then assign this field to another variable that will be passed to
		 * the bpf_probe_read function
		 */
		let pid_ref_var_t = pid.typ.pointer();
		let pid_ref_var = Variable::new(&pid_ref_var_t, None);
		let def = pid_ref_var.definition();

		let expr = Expr::reference(pid.expr());
		let assign = pid_ref_var.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * And extract the size of this thing
		 */
		let sizeof_pid = Variable::new(&Kind::size_t(), None);
		let def = sizeof_pid.definition();

		let call = sizeof.call(vec![pid_ref_var.expr()]);
		let assign = Lvalue::variable(&sizeof_pid).assign(&call);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Pointers to members of task struct
		 */

		let task_pid_ptr = Variable::new(&Kind::uint32_t().pointer(), None);
		let def = task_pid_ptr.definition();
		let expr = task.expr().ref_member("tgid").reference();

		let assign = task_pid_ptr.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * bpf_probe_read Function call to get the pid
		 */

		let args =
			vec![pid_ref_var.expr(), sizeof_pid.expr(), task_pid_ptr.expr()];
		let call = bpf_probe_read.call(args);
		bpf_scope_block.push(call.into());

		/*
		 * Initialize a variable to hold the tid
		 */
		let tid = Variable::new(&Kind::uint32_t(), None);
		let def = tid.definition();
		let assign = tid.lvalue().assign(&Expr::uint(0));
		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * And then assign a reference to this variable to another variable that
		 * will be passed to the bpf_probe_read function
		 */
		let tid_ref_var = Variable::new(&tid.typ.pointer(), None);
		let def = tid_ref_var.definition();

		let expr: Expr = tid.expr().reference();
		let assign = tid_ref_var.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Extract the size of this thing
		 */
		let sizeof_tid = Variable::new(&Kind::size_t(), None);
		let def = sizeof_tid.definition();
		let expr = sizeof.call(vec![tid_ref_var.expr()]);
		let assign = sizeof_tid.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Pointer into tid in task struct
		 */
		let task_tid_ptr = Variable::new(&Kind::uint32_t().pointer(), None);
		let def = task_tid_ptr.definition();
		let expr = task.expr().ref_member("tid").reference();
		let assign = task_tid_ptr.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * bpf_probe_read function call to get the tid
		 */

		let args =
			vec![tid_ref_var.expr(), sizeof_tid.expr(), task_tid_ptr.expr()];
		let expr = bpf_probe_read.call(args);
		bpf_scope_block.push(expr.into());

		/*
		 * Get nanosecond time
		 */

		let time = Variable::new(&Kind::uint64_t(), None);
		let def = time.definition();
		let expr = bpf_ktime_get_ns.call(vec![]);
		let assign = time.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Get syscall number
		 */
		let syscall_number = Variable::new(&Kind::uint64_t(), None);
		let expr = bpf_declaration
			.get_arg(0)
			.unwrap()
			.expr()
			.ref_member("syscall_number");
		let def = syscall_number.definition();
		let assign = syscall_number.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * A zero value for lookups
		 */
		let zero = Variable::new(&Kind::int(), None);
		let expr = Expr::int(0);
		let def = zero.definition();
		let assign = zero.lvalue().assign(&expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * If statement filtering the pid and syscall number
		 */

		let syscall_filter = Expr::binary(
			syscall_number.expr(),
			BinaryOperator::Eq,
			Expr::uint(0),
		);
		let pid_filter =
			Expr::binary(pid.expr(), BinaryOperator::Eq, target_pid.expr());
		let filt =
			Expr::binary(syscall_filter, BinaryOperator::And, pid_filter);

		/*
		 * ScopeBlock for if
		 */
		let mut if_scope_block = ScopeBlock::new();

		/*
		 * 0-initialize the syscall_event struct
		 */
		let syscall_event = Variable::new(&syscall_event_t, None);
		let def = syscall_event.definition();
		let assign = syscall_event.lvalue().assign(&Expr::cconst("{0}"));
		if_scope_block.push(def.into());
		if_scope_block.push(assign.into());

		/*
		 * Assign values to syscall_event struct
		 * e.pid = pid;
		 * e.tid = tid;
		 * e.duration = 0 ;
		 * e.syscall_number = syscall_number;
		 * e.start_time = time;
		 */
		if_scope_block.push(
			syscall_event
				.lvalue()
				.member("pid")
				.assign(&pid.expr())
				.into(),
		);
		if_scope_block.push(
			syscall_event
				.lvalue()
				.member("tid")
				.assign(&tid.expr())
				.into(),
		);
		if_scope_block.push(
			syscall_event
				.lvalue()
				.member("duration")
				.assign(&Expr::uint(0))
				.into(),
		);
		if_scope_block.push(
			syscall_event
				.lvalue()
				.member("syscall_number")
				.assign(&syscall_number.expr())
				.into(),
		);
		if_scope_block.push(
			syscall_event
				.lvalue()
				.member("start_time")
				.assign(&syscall_number.expr())
				.into(),
		);

		/*
		 * struct syscall_event_buffer *buffer = bpf_map_lookup_elem(&syscall_buffers, &zero);
		 * if (!buffer) {
		 *   bpf_printk("ERROR GETTING BUFFER");
		 *   return 0;
		 * }
		 */
		let buffer_ptr = Variable::new(&event_buffer_t.pointer(), None);
		let def = buffer_ptr.definition();
		let expr = bpf_map_lookup_elem.call(vec![
			syscall_buffer_map.expr().reference(),
			zero.expr().reference(),
		]);
		let assign = buffer_ptr.lvalue().assign(&expr);
		if_scope_block.push(def.into());
		if_scope_block.push(assign.into());

		/*
		 * Check if the buffer is null
		 */
		let buffer_check = Expr::unary(buffer_ptr.expr(), UnaryOperator::Not);
		let mut block = ScopeBlock::new();
		block.push(CodeUnit::Return(Expr::uint(0)));
		if_scope_block.push(IfBlock::from_parts(buffer_check, block).into());

		/*
		 * Check if the buffer length is < 256
		 * if (buffer->length < 256) {
		 *     buffer->buffer[buffer->length] = e;
		 *     buffer->length += 1;
		 * }
		 */
		let buffer_len_check = Expr::binary(
			buffer_ptr.expr().ref_member("length"),
			BinaryOperator::Lt,
			Expr::uint(256),
		);
		let mut block = ScopeBlock::new();
		let assign = buffer_ptr
			.lvalue()
			.ref_member("buffer")
			.offset(Expr::uint(1))
			.assign(&syscall_event.expr());
		block.push(assign.into());
		let assign = buffer_ptr
			.lvalue()
			.ref_member("length")
			.add_assign(Expr::uint(1));
		block.push(assign.into());

		if_scope_block
			.push(IfBlock::from_parts(buffer_len_check, block).into());

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
			Expr::uint(256),
		);
		let mut block = ScopeBlock::new();
		let expr = bpf_perf_event_output.call(vec![
			bpf_declaration
				.get_arg(0)
				.unwrap()
				.expr()
				.cast(Kind::void().pointer()),
			event_buffer_map.expr().reference(),
			Expr::cconst("BPF_F_CURRENT_CPU"),
			buffer_ptr.expr(),
			sizeof.call(vec![buffer_ptr.expr().deref()]),
		]);
		block.push(expr.into());

		if_scope_block
			.push(IfBlock::from_parts(buffer_full_check, block).into());

		/*
		 * Finally, we push the if scope block to the bpf scope block
		 */
		bpf_scope_block.push(IfBlock::from_parts(filt, if_scope_block).into());
		bpf_scope_block.push(CodeUnit::Return(Expr::uint(0).into()).into());

		//if (syscall_number == 17 && pid == target_pid) {

		/*
		 * Finally make the handl_sys_enter function
		 */
		let handle_sys_enter = BpfProgram::new(
			"handle_sys_enter",
			bpf_declaration,
			bpf_scope_block,
			"tp/raw_syscalls/sys_enter",
		);
		code_block.push(handle_sys_enter.definition().into());

		println!("{}", clang_format(&code_block.emit_code()).unwrap());
		assert_code_eq(exp, &code_block.emit_code());
	}

	#[test]
	fn simple_alignment() {
		let s = Struct::new(
			vec![
				("a".into(), Kind::char()),  // align 1, offset 0
				("b".into(), Kind::int()),   // align 4, offset 4
				("c".into(), Kind::char()),  // align 1, offset 8
				("d".into(), Kind::char()),  // align 1, offset 9
				("e".into(), Kind::__u64()), // align 8, offset 16
				("f".into(), Kind::char()),  // align 1, offset 24
			]
			.as_slice(),
		);

		// struct alignment is 8, size = 32

		assert_eq!(0, s.offsetof(&"a".into()).unwrap());
		assert_eq!(4, s.offsetof(&"b".into()).unwrap());
		assert_eq!(8, s.offsetof(&"c".into()).unwrap());
		assert_eq!(9, s.offsetof(&"d".into()).unwrap());
		assert_eq!(16, s.offsetof(&"e".into()).unwrap());
		assert_eq!(24, s.offsetof(&"f".into()).unwrap());
		assert_eq!(8, s.alignment());
		assert_eq!(32, s.size());
	}

	#[test]
	fn array_alignment() {
		let struct_kind = Kind::cstruct(
			&vec![
				("a".into(), Kind::char()),  // align 1, offset 0
				("b".into(), Kind::int()),   // align 4, offset 4
				("c".into(), Kind::char()),  // align 1, offset 8
				("d".into(), Kind::char()),  // align 1, offset 9
				("e".into(), Kind::__u64()), // align 8, offset 16
				("f".into(), Kind::char()),  // align 1, offset 24
			]
			.as_slice(),
		);
		let a_t = Kind::array(&struct_kind, 6);

		let s = Struct::new(
			vec![
				("a".into(), Kind::int()),  // align 1, offset 0,
				("b".into(), a_t.clone()),  // align 8, offset 8, size 32 * 6
				("c".into(), Kind::char()), // align 1, offset 200
			]
			.as_slice(),
		);

		assert_eq!(0, s.offsetof(&"a".into()).unwrap());
		assert_eq!(8, s.offsetof(&"b".into()).unwrap());
		assert_eq!(200, s.offsetof(&"c".into()).unwrap());

		// 32 * 6 for array, 8 for first int + 4 bytes padding, 1 for last char
		// + 7 bytes padding
		let exp_sz = 208;
		assert_eq!(exp_sz, s.size());
	}
}
