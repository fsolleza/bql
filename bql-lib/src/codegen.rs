use rand::prelude::*;
use std::sync::{
	Arc,
	atomic::{AtomicU64, Ordering::SeqCst},
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
pub enum ScalarValue {
	Null,
	Float(f64),
	Uint(u64),
	Bool(bool),
	Int(i64),
	Cstring(String),
	Const(String), // catchall for typeof, sizeof
}

impl ScalarValue {
	fn gen_expression(&self) -> String {
		match self {
			Self::Null => "null".into(),
			Self::Float(x) => format!("{}", x),
			Self::Uint(x) => format!("{}", x),
			Self::Bool(x) => format!("{}", x),
			Self::Int(x) => format!("{}", x),
			Self::Cstring(x) => format!("\"{}\"", x),
			Self::Const(x) => format!("{}", x),
		}
	}

	fn into_expr(self) -> Expr {
		Expr::ScalarValue(self)
	}
}

#[derive(Clone)]
pub struct Type(Arc<InnerType>);

impl std::ops::Deref for Type {
	type Target = InnerType;
	fn deref(&self) -> &Self::Target {
		&*self.0
	}
}

impl Type {
	fn void() -> Self { Type(Arc::new(InnerType::Void)) }
	fn int() -> Self { Type(Arc::new(InnerType::Int)) }
	fn char() -> Self { Type(Arc::new(InnerType::Char)) }
	fn __u32() -> Self { Type(Arc::new(InnerType::__U32)) }
	fn __u64() -> Self { Type(Arc::new(InnerType::__U64)) }
	fn uint32_t() -> Self { Type(Arc::new(InnerType::Uint32T)) }
	fn uint64_t() -> Self { Type(Arc::new(InnerType::Uint64T)) }
	fn int32_t() -> Self { Type(Arc::new(InnerType::Int32T)) }
	fn int64_t() -> Self { Type(Arc::new(InnerType::Int64T)) }
	fn size_t() -> Self { Type(Arc::new(InnerType::SizeT)) }
	//fn cstruct(s: Struct) -> Self { Type(Arc::new(InnerType::Struct(s))) }
	fn array(a: Array) -> Self { Type(Arc::new(InnerType::Array(a))) }
	fn bpf_map(m: BpfMap) -> Self { Type(Arc::new(InnerType::BpfMap(m))) }
	fn other(s: String) -> Self { Type(Arc::new(InnerType::Other(s))) }

	pub fn cstruct(fields: &[(String, Type)]) -> Self {
		Type(Arc::new(InnerType::Struct(Struct::new(fields))))
	}

	fn pointer(&self) -> Self {
		Type(Arc::new(InnerType::Pointer(Pointer { typ: self.clone() })))
	}

	pub fn definition(&self) -> TypeDefinition {
		TypeDefinition { typ: self.clone() }
	}

	pub fn is_pointer(&self) -> bool {
		match &*self.0 {
			InnerType::Pointer(_) => true,
			_ => false
		}
	}

	pub fn is_bpf_map(&self) -> bool {
		match &*self.0 {
			InnerType::BpfMap(_) => true,
			_ => false
		}
	}
}

#[derive(Clone)]
pub enum InnerType {
	Void,
	Int,
	Char,
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

impl InnerType {
	pub fn gen_signature(&self) -> String {
		match self {
			Self::Int => "int".into(),
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
	typ: Type,
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
pub enum Expr {
	ScalarValue(ScalarValue),
	Variable(Variable),
	Member(Member),
	Reference(Reference),
	BinaryExpr(BinaryExpr),
	FunctionCall(FunctionCall),
}

impl Expr {
	pub fn gen_expression(&self) -> String {
		match self {
			Self::ScalarValue(x) => x.gen_expression(),
			Self::Variable(x) => x.gen_expression(),
			Self::Member(x) => x.gen_expression(),
			Self::Reference(x) => x.gen_expression(),
			Self::BinaryExpr(x) => x.gen_expression(),
			Self::FunctionCall(x) => x.gen_expression(),
		}
	}

	pub fn reference(self) -> Self {
		Self::Reference(Reference::new(Box::new(self)))
	}

	pub fn member(self, member: &str) -> Self {
		Self::Member(Member::new(self, member, false))
	}

	pub fn ref_member(self, member: &str) -> Self {
		Self::Member(Member::new(self, member, true))
	}

	pub fn gen_code_unit(&self) -> String {
		let mut s = self.gen_expression();
		s.push_str(";\n");
		s
	}
}

impl Into<Expr> for ScalarValue {
	fn into(self) -> Expr {
		Expr::ScalarValue(self)
	}
}

impl Into<Expr> for Variable {
	fn into(self) -> Expr {
		Expr::Variable(self)
	}
}

//impl Into<Expr> for VariableMember {
//	fn into(self) -> Expr {
//		Expr::VariableMember(self)
//	}
//}

impl Into<Expr> for Reference {
	fn into(self) -> Expr {
		Expr::Reference(self)
	}
}

impl Into<Expr> for BinaryExpr {
	fn into(self) -> Expr {
		Expr::BinaryExpr(self)
	}
}

impl Into<Expr> for FunctionCall {
	fn into(self) -> Expr {
		Expr::FunctionCall(self)
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

pub struct Member {
	expr: Box<Expr>,
	member: String,
	is_ref: bool,
}

impl Member {
	pub fn new(expr: Expr, member: &str, is_ref: bool) -> Self {
		Member { expr: Box::new(expr), member: member.into(), is_ref }
	}

	pub fn gen_expression(&self) -> String {
		if self.is_ref {
			format!("{}->{}", self.expr.gen_expression(), self.member)
		} else {
			format!("{}.{}", self.expr.gen_expression(), self.member)
		}
	}
}

pub enum BinaryOperator {
	Add,
	Sub,
	Eq,
	Neq,
}

impl BinaryOperator {
	fn gen_symbol(&self) -> String {
		match self {
			Self::Add => "+".into(),
			Self::Sub => "-".into(),
			Self::Eq => "==".into(),
			Self::Neq => "!=".into(),
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
		format!("{} {} {}",
			   self.lr.0.gen_expression(),
			   self.op.gen_symbol(),
			   self.lr.1.gen_expression())
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
	bpf: BpfProgramRef,
}

impl BpfProgramDefinition {
	pub fn gen_code_unit(&self) -> String {
		self.bpf.gen_definition()
	}
}

impl Into<BpfProgramDefinition> for &BpfProgramRef {
	fn into(self) -> BpfProgramDefinition {
		BpfProgramDefinition {
			bpf: self.clone(),
		}
	}
}

pub enum CodeUnit {
	Include(Include),
	TypeDefinition(TypeDefinition),
	FunctionDefinition(FunctionDefinition),
	VariableDefinition(VariableDefinition),
	LvalueAssignment(LvalueAssignment),
	Expr(Expr),
	If(IfBlock),
	ScopeBlock(ScopeBlock),
	BpfProgramDefinition(BpfProgramDefinition),
}

impl CodeUnit {
	pub fn gen_code_unit(&self) -> String {
		match self {
			Self::TypeDefinition(x) => x.gen_code_unit(),
			Self::VariableDefinition(x) => x.gen_code_unit(),
			Self::FunctionDefinition(x) => x.gen_code_unit(),
			Self::Expr(x) => x.gen_code_unit(),
			Self::If(x) => x.gen_code_unit(),
			Self::Include(x) => x.gen_code_unit(),
			Self::ScopeBlock(x) => x.gen_code_unit(),
			Self::BpfProgramDefinition(x) => x.gen_code_unit(),
			Self::LvalueAssignment(x) => x.gen_code_unit(),
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

impl Into<CodeUnit> for TypeDefinition {
	fn into(self) -> CodeUnit {
		CodeUnit::TypeDefinition(self)
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

pub struct TypeDefinition {
	typ: Type
}

impl TypeDefinition {
	fn gen_code_unit(&self) -> String {
		let mut s = self.typ.gen_definition();
		s.push_str(";\n");
		s
	}
}

pub struct VariableDefinition {
	var: Variable
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
			"{}\n{}",
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

struct FunctionDeclaration {
	ret: Type,
	arg_types: Vec<Type>,
	arg_vars: Vec<Variable>,
}

impl FunctionDeclaration {
	pub fn new(return_type: &Type, argument_types: Vec<Type>) -> Self {
		let arg_vars: Vec<Variable> = argument_types.iter().cloned().map(|x| {
			Variable::new(&x, None).into()
		}).collect();

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

#[derive(Clone)]
pub struct Function {
	inner: Arc<InnerFunction>
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
		definition: Option<ScopeBlock>
	) -> Self {
		Self {
			inner: Arc::new(InnerFunction {
				name: name.into(), declaration, definition
			})
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
		Expr::FunctionCall(FunctionCall { func: self.clone(), args })
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
		let mut args = String::new();
		for (i, arg) in decl.arg_vars.iter().enumerate() {
			args.push_str(&arg.gen_definition());
			//args.push_str(&format!(" arg_{}", i));
			if i < decl.arg_vars.len() - 1 {
				args.push_str(", ");
			}
		}
		Some(format!(
			"{} {}({})",
			decl.ret.gen_signature(),
			&self.name,
			args
		))
	}

	pub fn gen_definition(&self) -> Option<String> {
		let defn = self.definition.as_ref()?;
		Some(format!("{} {}", self.gen_declaration()?, defn.gen_code_block()))
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
	inner: Arc<InnerVariable>
}

impl std::ops::Deref for Variable {
	type Target = InnerVariable;
	fn deref(&self) -> &Self::Target {
		&*self.inner
	}
}

impl Variable {

	pub fn new(typ: &Type, qualifiers: Option<&[Qualifier]>) -> Self {
		let id = VARID.fetch_add(1, SeqCst);
		Self::new_with_id(typ, qualifiers, id)
	}

	pub fn new_with_id(
		typ: &Type,
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
				}
			})
		}
	}

	pub fn definition(&self) -> VariableDefinition {
		VariableDefinition { var: self.clone() }
	}

	pub fn lvalue(&self) -> Lvalue {
		Lvalue::Variable(self.clone())
	}

	pub fn expr(&self) -> Expr {
		Expr::Variable(self.clone())
	}
}

pub struct InnerVariable {
	pub typ: Type,
	pub qualifiers: Option<Vec<Qualifier>>,
	id: u64,
}

impl InnerVariable {
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
		}
		s
	}

	fn gen_expression(&self) -> String {
		format!("var_{}", self.id)
	}
}

#[derive(Clone)]
pub struct Array {
	typ: Type,
	sz: usize,
	id: u64,
}

impl Array {
	pub fn new(typ: &Type, sz: usize) -> Self {
		let id = TYPEID.fetch_add(1, SeqCst);
		Self::new_with_id(typ, sz, id)
	}

	pub fn new_with_id(typ: &Type, sz: usize, id: u64) -> Self {
		Self { typ: typ.clone(), sz, id }
	}

	pub fn gen_signature(&self) -> String {
		format!("ArrType_{}", self.id)
	}

	pub fn gen_definition(&self) -> String {
		format!("typedef {} ArrType_{}[{}]",
				self.typ.gen_signature(),
				self.id,
				self.sz)
	}
}

#[derive(Clone)]
pub struct Struct {
	fields: Vec<(String, Type)>,
	id: u64,
}

impl Struct {

	pub fn new(fields: &[(String, Type)]) -> Self {
		Self::new_with_id(fields, TYPEID.fetch_add(1, SeqCst))
	}

	pub fn new_with_id(fields: &[(String, Type)], id: u64) -> Self {
		Self {
			fields: fields.into(),
			id,
		}
	}

	pub fn gen_signature(&self) -> String {
		format!("struct_{}", self.id)
	}

	pub fn gen_definition(&self) -> String {
		let mut s: String = format!("typedef struct struct_{} {{\n", self.id);

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
	key: Type,
	value: Type,
	max_entries: u64,
	id: u64,
}

impl PerCpuArray {
	pub fn new_with_id(
		key: &Type,
		value: &Type,
		max_entries: u64,
		id: u64
	) -> Self {
		Self { key: key.clone(), value: value.clone(), max_entries, id }
	}

	pub fn new(
		key: &Type,
		value: &Type,
		max_entries: u64,
	) -> Self {
		Self::new_with_id(key, value, max_entries, TYPEID.fetch_add(1, SeqCst))
	}

	pub fn gen_signature(&self) -> String {
		format!("per_cpu_array_t_{}", self.id)
	}

	pub fn gen_definition(&self) -> String {
		let map_type = format!("per_cpu_array_t_{}", self.id);
		let mut s: String = format!("typedef struct {} {{\n", map_type);
		let k = format!("__type(key, {});\n", self.key.gen_signature());
		let v = format!("__type(value, {});\n", self.value.gen_signature());
		let e = format!("__max_entries(max_entries, {});\n", self.max_entries);
		s.push_str("__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);\n");
		s.push_str(&k);
		s.push_str(&v);
		s.push_str(&e);
		s.push_str(&format!("}} {}", map_type));
		s
	}
}

#[derive(Clone)]
pub struct PerfEventArray {
	key_size: ScalarValue,
	value_size: ScalarValue,
	id: u64,
}

impl PerfEventArray {
	pub fn new_with_id(
		key_size: ScalarValue,
		value_size: ScalarValue,
		id: u64
	) -> Self {
		Self { key_size, value_size, id }
	}

	pub fn new(
		key_size: ScalarValue,
		value_size: ScalarValue,
	) -> Self {
		Self::new_with_id(key_size, value_size, TYPEID.fetch_add(1, SeqCst))
	}


	pub fn gen_signature(&self) -> String {
		format!("perf_event_array_t_{}", self.id)
	}

	pub fn gen_definition(&self) -> String {
		let map_type = self.gen_signature();
		let mut s: String = format!("typedef struct {} {{\n", map_type);
		let k = format!("__uint(key_size, {});\n", self.key_size.gen_expression());
		let v = format!("__uint(value_size, {});\n", self.value_size.gen_expression());
		s.push_str("__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);\n");
		s.push_str(&k);
		s.push_str(&v);
		s.push_str(&format!("}} {}", map_type));
		s
	}
}

pub struct BpfProgram {
	func: Function,
	hook: String,
}

type BpfProgramRef = Arc<BpfProgram>;

impl BpfProgram {
	pub fn new(
		func_name: &str,
		decl: FunctionDeclaration,
		def: ScopeBlock,
		hook: &str
	) -> Self {
		let func = Function::new_from_required_parts(func_name, decl, def);
		BpfProgram { func, hook: hook.into() }
	}

	pub fn gen_definition(&self) -> String {
		format!("SEC(\"{}\")\n{}", self.hook, self.func.gen_definition().unwrap())
	}

	pub fn get_arg(&self, idx: usize) -> Variable {
		self.func.get_arg(idx).unwrap()
	}
}

pub enum Lvalue {
	Variable(Variable),
	Member(LvalueMember),
}

impl Lvalue {
	pub fn member(self, member: &str) -> Self {
		Lvalue::Member(LvalueMember {
			parent: Box::new(self),
			member: member.into(),
		})
	}

	pub fn gen_expression(&self) -> String {
		match self {
			Self::Variable(x) => x.gen_expression(),
			Self::Member(x) => format!("*{}", x.gen_expression()),
		}
	}

	pub fn assign(self, expr: Expr) -> LvalueAssignment {
		LvalueAssignment {
			lvalue: self,
			expr,
		}
	}
}

pub struct LvalueMember {
	parent: Box<Lvalue>,
	member: String,
}

impl LvalueMember {
	pub fn gen_expression(&self) -> String {
		format!("{}.{}", self.parent.gen_expression(), self.member)
	}
}

pub struct LvalueAssignment {
	lvalue: Lvalue,
	expr: Expr,
}

impl LvalueAssignment {
	pub fn gen_code_unit(&self) -> String {
		format!("{} = {};\n",
				self.lvalue.gen_expression(),
				self.expr.gen_expression())
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

	//#[test]
	//fn array_def1() {
	//	let exp = "typedef char ArrType_1[3]";
	//	let arr = Type::new_array_with_id(Type::Char.into(), 3, 1);
	//	assert_code_eq(exp, &arr.gen_definition());
	//}

	//#[test]
	//fn array_def2() {
	//	let exp = "typedef struct_0 ArrType_1[3]";

	//	let fields = [
	//		("field1".into(), Type::Int.into()),
	//		("field2".into(), Type::Char.into())
	//	];
	//	let s = Type::new_struct_with_id(&fields, 0).into();
	//	let arr = Array::new_with_id(s, 3, 1);
	//	assert_code_eq(exp, &arr.gen_definition());
	//}

	//#[test]
	//fn struct_def1() {
	//	let exp = "
	//		typedef struct struct_0{
	//			field1 int;
	//			field2 ArrType_1;
	//		} struct_0
	//	";
	//	let arr = Type::new_array_with_id(Type::Int.into(), 5, 1).into();
	//	let fields = [
	//		("field1".into(), Type::Int.into()),
	//		("field2".into(), arr)
	//	];
	//	let s = Type::new_struct_with_id(&fields, 0);
	//	assert_code_eq(exp, &s.gen_definition());
	//}

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

			typedef uint32_t ArrType_0[6];

			typedef struct struct_0 {
				uint64_t pad;
				int64_t syscall_number;
				ArrType_0 args;
			} struct_0;

			typedef struct struct_1 {
				uint32_t pid;
				uint32_t tid;
				uint64_t syscall_number;
				uint64_t start_time;
				uint64_t duration;
			} struct_1;

			typedef struct_1 ArrType_2[256];

			typedef struct struct_2  {
				uint32_t length;
				ArrType_2 buffer;
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


		let mut code_block = ScopeBlock::new();
		code_block.push(Include::FilePath("vmlinux.h".into()).into());
		code_block.push(Include::Library("bpf/bpf_core_read.h".into()).into());
		code_block.push(Include::Library("bpf/bpf_helpers.h".into()).into());

		/*
		 * My Pid variable declaration and definition
		 */
		let qualifiers = &[Qualifier::Const, Qualifier::Volatile];
		let my_pid =
			Variable::new(&Type::uint32_t(), Some(qualifiers));
		let def = my_pid.definition();

		let value = Expr::ScalarValue(ScalarValue::Uint(12345));
		let assign = Lvalue::Variable(my_pid.clone()).assign(value);
		code_block.push(def.into());
		code_block.push(assign.into());

		/*
		 * Target PID variable declaration and definition
		 */
		let q = &[Qualifier::Const, Qualifier::Volatile];
		let target_pid =
			Variable::new(&Type::uint32_t(), Some(q));
		let def = target_pid.definition();

		let value = Expr::ScalarValue(ScalarValue::Uint(67890));
		let assign = Lvalue::Variable(target_pid.clone()).assign(value);

		code_block.push(def.into());
		code_block.push(assign.into());

		/*
		 * Argument array in the sysenter BPF hook context
		 */
		let sysenter_args_t: Type =
			Type::array(Array::new(&Type::uint32_t(), 6));
		let def: TypeDefinition = sysenter_args_t.definition();
		code_block.push(def.into());

		/*
		 * Struct 0: BPF ctx
		 */
		let sys_enter_ctx: Type = Type::cstruct(
				&[
				("pad".into(), Type::uint64_t()),
				("syscall_number".into(), Type::int64_t()),
				("args".into(), sysenter_args_t.clone()),
				],
		);
		let def = sys_enter_ctx.definition();
		code_block.push(def.into());

		/*
		 * Struct 1: Syscall Event
		 */
		let syscall_event_t: Type = Type::cstruct(
				&[
				("pid".into(), Type::uint32_t()),
				("tid".into(), Type::uint32_t()),
				("syscall_number".into(), Type::uint64_t()),
				("start_time".into(), Type::uint64_t()),
				("duration".into(), Type::uint64_t()),
				],
		);
		let def = syscall_event_t.definition();
		code_block.push(def.into());

		/*
		 * Array 1: Array used in the event buffer (struct 2)
		 */
		let buffer_array_t = Type::array(Array::new(&syscall_event_t, 256));
		let def = buffer_array_t.definition();
		code_block.push(def.into());

		/*
		 * Struct 2: A buffer of such syscall events
		 */
		let event_buffer_t = Type::cstruct(
			&[
				("length".into(), Type::uint32_t()),
				("buffer".into(), buffer_array_t.clone()),
			],
		);
		let def = event_buffer_t.definition();
		code_block.push(def.into());

		/*
		 * Perf Event Array to send event buffers to user space
		 */
		let event_buffer_map_t = Type::bpf_map(BpfMap::PerfEventArray(
				PerfEventArray::new(
					ScalarValue::Const("sizeof(int)".into()),
					ScalarValue::Const("sizeof(int)".into()),
					)
				));
		let def = event_buffer_map_t.definition();
		code_block.push(def.into());

		/*
		 * Define the actual perf event array map for event buffers
		 */
		let event_buffer_map = Variable::new(&event_buffer_map_t, None);
		let def: VariableDefinition = event_buffer_map.definition();
		code_block.push(def.into());

		/*
		 * Define a few functions we will use
		 */
		let sizeof = Function::with_name("sizeof");

		let bpf_probe_read = Function::with_name("bpf_probe_read");

		let bpf_ktime_get_ns = Function::with_name("bpf_ktime_get_ns");

		/*
		 * Function declaration for BPF program
		 */
		let ret: Type = Type::int();
		let args: Vec<Type> =
			vec![sys_enter_ctx.pointer()];
		let bpf_declaration = FunctionDeclaration::new(&ret, args);

		/*
		 * Begin building the scope block for the function
		 */
		let mut bpf_scope_block = ScopeBlock::new();

		/*
		 * Get task struct into a variable
		 */
		let task_struct_t = Type::other("struct task_struct".into());
		let task_struct_ptr_t = task_struct_t.pointer();

		let task = Variable::new(&task_struct_ptr_t, None);
		let def = task.definition();

		let bpf_get_current_task = Function::with_name("bpf_get_current_task");

		let expr = bpf_get_current_task.call(Vec::new());

		let assign = task.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Initialize a variable to hold the pid
		 */
		let pid = Variable::new(&Type::uint32_t(), None);

		let def = pid.definition();
		let assign = pid.lvalue().assign(ScalarValue::Uint(0).into_expr());

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
		let assign = pid_ref_var.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * And extract the size of this thing
		 */
		let sizeof_pid = Variable::new(&Type::size_t(), None);
		let def = sizeof_pid.definition();

		let call = sizeof.call(vec![pid_ref_var.expr()]);
		let assign = Lvalue::Variable(sizeof_pid.clone()).assign(call);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Pointers to members of task struct
		 */

		let task_pid_ptr =
			Variable::new(&Type::uint32_t().pointer(), None);
		let def = task_pid_ptr.definition();
		let expr = task.expr().ref_member("tgid").reference();

		let assign = task_pid_ptr.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * bpf_probe_read Function call to get the pid
		 */

		let args = vec![
			pid_ref_var.expr(),
			sizeof_pid.expr(),
			task_pid_ptr.expr()
		];
		let call = bpf_probe_read.call(args);
		bpf_scope_block.push(call.into());


		/*
		 * Initialize a variable to hold the tid
		 */
		let tid = Variable::new(&Type::uint32_t(), None);
		let def = tid.definition();
		let assign = tid.lvalue().assign(ScalarValue::Uint(0).into());
		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * And then assign a reference to this variable to another variable that
		 * will be passed to the bpf_probe_read function
		 */
		let tid_ref_var = Variable::new(&tid.typ.pointer(), None);
		let def = tid_ref_var.definition();

		let expr: Expr = tid.expr().reference();
		let assign = tid_ref_var.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Extract the size of this thing
		 */
		let sizeof_tid = Variable::new(&Type::size_t(), None);
		let def = sizeof_tid.definition();
		let expr = sizeof.call(vec![tid_ref_var.expr()]);
		let assign = sizeof_tid.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Pointer into tid in task struct
		 */
		let task_tid_ptr = Variable::new(&Type::uint32_t().pointer(), None);
		let def = task_tid_ptr.definition();
		let expr = task.expr().ref_member("tid").reference();
		let assign = task_tid_ptr.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * bpf_probe_read function call to get the tid
		 */

		let args = vec![
			tid_ref_var.expr(),
			sizeof_tid.expr(),
			task_tid_ptr.expr()
		];
		let expr = bpf_probe_read.call(args);
		bpf_scope_block.push(expr.into());

		/*
		 * Get nanosecond time
		 */

		let time = Variable::new(&Type::uint64_t(), None);
		let def = time.definition();
		let expr = bpf_ktime_get_ns.call(vec![]);
		let assign = time.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Get syscall number
		 */
		let syscall_number = Variable::new(&Type::uint64_t(), None);
		let expr = bpf_declaration
			.get_arg(0)
			.unwrap()
			.expr()
			.ref_member("syscall_number");
		let def = syscall_number.definition();
		let assign = syscall_number.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * A zero value for lookups
		 */
		let zero = Variable::new(&Type::int(), None);
		let expr: Expr = ScalarValue::Int(0).into();
		let def = zero.definition();
		let assign = zero.lvalue().assign(expr);

		bpf_scope_block.push(def.into());
		bpf_scope_block.push(assign.into());

		/*
		 * Finally make the handl_sys_enter function
		 */
		let handle_sys_enter: BpfProgramRef = BpfProgram::new(
			"handle_sys_enter",
			bpf_declaration,
			bpf_scope_block,
			"tp/raw_syscalls/sys_enter"
			).into();
		let handle_sys_enter_def: BpfProgramDefinition = (&handle_sys_enter).into();
		code_block.push(handle_sys_enter_def.into());


		println!("{}", clang_format(&code_block.gen_code_block()).unwrap());
		assert_code_eq(exp, &code_block.gen_code_block());
	}
}
