use rand::prelude::*;
use std::sync::Arc;

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
}

#[derive(Clone)]
pub enum Type {
	Void,
	Int,
	Char,
	__U32,
	__U64,
	Uint32T,
	Uint64T,
	Int32T,
	Int64T,
	Struct(Struct),
	Array(Array),
	Pointer(Pointer),
	BpfMap(BpfMap),
	Other(String),
}

// Types can be referenced / used / initialized many times
type TypeRef = Arc<Type>;

impl Type {
	pub fn gen_signature(&self) -> String {
		match self {
			Self::Int => "int".into(),
			Self::__U32 => "__u32".into(),
			Self::__U64 => "__u64".into(),
			Self::Uint32T => "uint32_t".into(),
			Self::Uint64T => "uint64_t".into(),
			Self::Int32T => "int32_t".into(),
			Self::Int64T => "int64_t".into(),
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
			Self::Void => "void".into(),
			Self::Struct(s) => s.gen_definition(),
			Self::Array(a) => a.gen_definition(),
			Self::Pointer(p) => p.gen_definition(),
			Self::BpfMap(m) => m.gen_definition(),
			Self::Other(x) => x.clone(),
		}
	}

	pub fn new_struct(fields: &[(String, TypeRef)]) -> Self {
		let s = Struct::new(fields);
		Self::Struct(s)
	}

	pub fn new_struct_with_id(fields: &[(String, TypeRef)], id: u64) -> Self {
		let s = Struct::new_with_id(fields, id);
		Self::Struct(s)
	}

	pub fn new_array(typ: TypeRef, sz: usize) -> Self {
		Self::Array(Array::new(typ, sz))
	}

	pub fn new_array_with_id(typ: TypeRef, sz: usize, id: u64) -> Self {
		Self::Array(Array::new_with_id(typ, sz, id))
	}

	pub fn into_ref(self) -> TypeRef {
		self.into()
	}
}

#[derive(Clone)]
pub struct Pointer {
	typ: TypeRef,
}

impl Pointer {
	pub fn new(typ: TypeRef) -> Self {
		Self { typ }
	}

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
	Variable(VariableRef),
	VariableMember(VariableMember),
	BinaryExpr(BinaryExpr),
	FunctionCall(FunctionCall),
}

impl Expr {
	pub fn gen_expression(&self) -> String {
		match self {
			Self::ScalarValue(x) => x.gen_expression(),
			Self::Variable(x) => x.gen_expression(),
			Self::BinaryExpr(x) => x.gen_expression(),
			Self::FunctionCall(x) => x.gen_expression(),
			Self::VariableMember(x) => x.gen_expression(),
		}
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

impl Into<Expr> for VariableRef {
	fn into(self) -> Expr {
		Expr::Variable(self)
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

impl Into<Expr> for VariableMember {
	fn into(self) -> Expr {
		Expr::VariableMember(self)
	}
}


pub struct VariableMember {
	variable: VariableRef,
	member: String,
}

impl VariableMember {
	pub fn new(variable: VariableRef, member: &str) -> Self {
		VariableMember { variable, member: member.into() }
	}

	pub fn gen_expression(&self) -> String {
		match &(*self.variable.typ) {
			Type::Pointer(_) => {
				format!("{}->{}", self.variable.gen_expression(), self.member)
			},
			_ => format!("{}.{}", self.variable.gen_expression(), self.member)
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
	left: VariableRef,
	right: VariableRef,
	op: BinaryOperator,
}

impl BinaryExpr {
	pub fn gen_expression(&self) -> String {
		let mut s = String::new();
		format!("{} {} {}",
			   self.left.gen_expression(),
			   self.op.gen_symbol(),
			   self.right.gen_expression())
	}
}

pub struct FunctionCall {
	func: FunctionRef,
	args: Vec<VariableRef>,
}

impl FunctionCall {
	pub fn new(func: FunctionRef, args: Vec<VariableRef>) -> Self {
		FunctionCall { func, args }
	}
	pub fn gen_expression(&self) -> String {
		self.func.gen_call(&self.args)
	}
}

pub struct FunctionDefinition {
	func: FunctionRef,
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
	VariableAssignment(VariableAssignment),
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
			Self::VariableAssignment(x) => x.gen_code_unit(),
			Self::Expr(x) => x.gen_code_unit(),
			Self::If(x) => x.gen_code_unit(),
			Self::Include(x) => x.gen_code_unit(),
			Self::ScopeBlock(x) => x.gen_code_unit(),
			Self::BpfProgramDefinition(x) => x.gen_code_unit(),
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

impl Into<CodeUnit> for VariableAssignment {
	fn into(self) -> CodeUnit {
		CodeUnit::VariableAssignment(self)
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
	typ: TypeRef
}

impl TypeDefinition {
	fn gen_code_unit(&self) -> String {
		let mut s = self.typ.gen_definition();
		s.push_str(";\n");
		s
	}
}

impl Into<TypeDefinition> for &TypeRef {
	fn into(self) -> TypeDefinition {
		TypeDefinition {
			typ: self.clone(),
		}
	}
}

pub struct VariableDefinition {
	var: VariableRef
}

impl VariableDefinition {
	fn gen_code_unit(&self) -> String {
		let mut s = self.var.gen_definition();
		s.push_str(";\n");
		s
	}
}

impl Into<VariableDefinition> for &VariableRef {
	fn into(self) -> VariableDefinition {
		VariableDefinition {
			var: self.clone(),
		}
	}
}

pub struct IfBlock {
	expr: VariableRef,
	block: ScopeBlock,
}

impl IfBlock {
	pub fn from_parts(expr: VariableRef, block: ScopeBlock) -> Self {
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
	ret: TypeRef,
	args: Vec<TypeRef>,
	vars: Vec<VariableRef>,
}

impl FunctionDeclaration {
	pub fn new(return_type: TypeRef, argument_types: Vec<TypeRef>) -> Self {
		let vars: Vec<VariableRef> = argument_types.iter().cloned().map(|x| {
			Variable::new(x, None).into()
		}).collect();

		Self {
			ret: return_type,
			args: argument_types,
			vars,
		}
	}

	pub fn get_arg_var(&self, idx: usize) -> Option<VariableRef> {
		Some(self.vars.get(idx)?.clone())
	}
}

pub struct Function {
	name: String,
	declaration: Option<FunctionDeclaration>,
	definition: Option<ScopeBlock>,
}

// Functions can be referenced / called many times
type FunctionRef = Arc<Function>; 

impl Function {
	pub fn with_name(name: &str) -> Self {
		Self::from_optional_parts(name, None, None)
	}

	pub fn from_optional_parts(
		name: &str,
		declaration: Option<FunctionDeclaration>,
		definition: Option<ScopeBlock>
	) -> Self {
		Self { name: name.into(), declaration, definition }
	}

	pub fn new_from_required_parts(
		name: &str,
		decl: FunctionDeclaration,
		def: ScopeBlock,
	) -> Self {
		Self::from_optional_parts(name, Some(decl), Some(def))
	}

	pub fn get_arg_var(&self, idx: usize) -> Option<VariableRef> {
		self.declaration.as_ref()?.get_arg_var(idx)
	}

	pub fn gen_declaration(&self) -> Option<String> {
		let decl = self.declaration.as_ref()?;
		let mut args = String::new();
		for (i, arg) in decl.args.iter().enumerate() {
			args.push_str(&arg.gen_signature());
			args.push_str(&format!(" arg_{}", i));
			if i < decl.args.len() - 1 {
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

	pub fn gen_call(&self, args: &[VariableRef]) -> String {
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

pub struct VariableAssignment {
	variable: VariableRef,
	expr: Expr,
}

impl VariableAssignment {
	pub fn new(variable: VariableRef, expr: Expr) -> Self {
		Self { variable, expr, }
	}

	pub fn gen_code_unit(&self) -> String {
		format!("{} = {};\n",
				self.variable.gen_expression(),
				self.expr.gen_expression())
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
	typ: TypeRef,
	id: u64,
	qualifiers: Option<Vec<Qualifier>>,
}

// Variables can be used or referenced or assigned to multiple times
type VariableRef = Arc<Variable>;

impl Variable {
	pub fn new(typ: TypeRef, qualifiers: Option<&[Qualifier]>) -> Self {
		let id = thread_rng().gen();
		Self::new_with_id(typ, qualifiers, id)
	}

	pub fn new_with_id(
		typ: TypeRef,
		qualifiers: Option<&[Qualifier]>,
		id: u64,
	) -> Self {
		Self {
			typ,
			id,
			qualifiers: {
				match qualifiers {
					None => None,
					Some(x) => Some(x.into()),
				}
			}
		}
	}

	pub fn gen_definition(&self) -> String {
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
		match &*self.typ {
			Type::BpfMap(_) => s.push_str(" SEC(\".maps\")"),
			_ => {},
		}
		s
	}

	pub fn gen_expression(&self) -> String {
		format!("var_{}", self.id)
	}

	pub fn into_ref(self) -> VariableRef {
		self.into()
	}
}

#[derive(Clone)]
pub struct Array {
	typ: TypeRef,
	sz: usize,
	id: u64,
}

impl Array {
	pub fn new(typ: TypeRef, sz: usize) -> Self {
		let id = thread_rng().gen();
		Self::new_with_id(typ, sz, id)
	}

	pub fn new_with_id(typ: TypeRef, sz: usize, id: u64) -> Self {
		Self { typ, sz, id }
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
	fields: Vec<(String, TypeRef)>,
	id: u64,
}

impl Struct {

	pub fn new(fields: &[(String, TypeRef)]) -> Self {
		Self::new_with_id(fields, thread_rng().gen())
	}

	pub fn new_with_id(fields: &[(String, TypeRef)], id: u64) -> Self {
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
	key: TypeRef,
	value: TypeRef,
	max_entries: u64,
	id: u64,
}

impl PerCpuArray {
	pub fn new_with_id(
		key: TypeRef,
		value: TypeRef,
		max_entries: u64,
		id: u64
	) -> Self {
		Self { key, value, max_entries, id }
	}

	pub fn new(
		key: TypeRef,
		value: TypeRef,
		max_entries: u64,
	) -> Self {
		Self::new_with_id(key, value, max_entries, thread_rng().gen())
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
		Self::new_with_id(key_size, value_size, thread_rng().gen())
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

	pub fn get_arg_var(&self, idx: usize) -> VariableRef {
		self.func.get_arg_var(idx).unwrap()
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
	fn array_def1() {
		let exp = "typedef char ArrType_1[3]";
		let arr = Type::new_array_with_id(Type::Char.into(), 3, 1);
		assert_code_eq(exp, &arr.gen_definition());
	}

	#[test]
	fn array_def2() {
		let exp = "typedef struct_0 ArrType_1[3]";

		let fields = [
			("field1".into(), Type::Int.into()),
			("field2".into(), Type::Char.into())
		];
		let s = Type::new_struct_with_id(&fields, 0).into();
		let arr = Array::new_with_id(s, 3, 1);
		assert_code_eq(exp, &arr.gen_definition());
	}

	#[test]
	fn struct_def1() {
		let exp = "
			typedef struct struct_0{
				field1 int;
				field2 ArrType_1;
			} struct_0
		";
		let arr = Type::new_array_with_id(Type::Int.into(), 5, 1).into();
		let fields = [
			("field1".into(), Type::Int.into()),
			("field2".into(), arr)
		];
		let s = Type::new_struct_with_id(&fields, 0);
		assert_code_eq(exp, &s.gen_definition());
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

		let qualifiers = &[Qualifier::Const, Qualifier::Volatile];
		let var0 = Variable::new_with_id(
			Type::Uint32T.into(),
			Some(qualifiers),
			0
		).into_ref();
		let var0_def: VariableDefinition = (&var0).into();
		code_block.push(var0_def.into());

		let qualifiers = &[Qualifier::Const, Qualifier::Volatile];
		let var1 = Variable::new_with_id(
			Type::Uint32T.into(),
			Some(qualifiers),
			1
		).into_ref();
		let var1_def: VariableDefinition = (&var1).into();
		code_block.push(var1_def.into());

		let value = Expr::ScalarValue(ScalarValue::Uint(12345));
		let assign = VariableAssignment::new(var0.clone(), value);
		code_block.push(assign.into());

		let value = Expr::ScalarValue(ScalarValue::Uint(67890));
		let assign = VariableAssignment::new(var1.clone(), value);
		code_block.push(assign.into());

		/*
		 * Array 0: Arguments in the BPF function call
		 */
		let array0: TypeRef =
			Type::Array(Array::new_with_id(Type::Uint32T.into(), 6, 0)).into();
		let array0_def: TypeDefinition = (&array0).into();
		code_block.push(array0_def.into());

		/*
		 * Struct 0: BPF ctx
		 */
		let sys_enter_ctx: TypeRef = Type::Struct(Struct::new_with_id(
			&[
				("pad".into(), Type::Uint64T.into()),
				("syscall_number".into(), Type::Int64T.into()),
				("args".into(), array0.clone()),
			],
			0
		)).into();
		let struct_def: TypeDefinition = (&sys_enter_ctx).into();
		code_block.push(struct_def.into());

		/*
		 * Struct 1: Syscall Event
		 */
		let struct1: TypeRef = Type::Struct(Struct::new_with_id(
			&[
				("pid".into(), Type::Uint32T.into()),
				("tid".into(), Type::Uint32T.into()),
				("syscall_number".into(), Type::Uint64T.into()),
				("start_time".into(), Type::Uint64T.into()),
				("duration".into(), Type::Uint64T.into()),
			],
			1
		)).into();
		let struct_def: TypeDefinition = (&struct1).into();
		code_block.push(struct_def.into());

		/*
		 * Array 1: Array used in the event buffer (struct 2)
		 */
		let array1: TypeRef =
			Type::Array(Array::new_with_id(struct1.clone(), 256, 2)).into();
		let array1_def: TypeDefinition = (&array1).into();
		code_block.push(array1_def.into());

		/*
		 * Struct 2: A buffer of such syscall events
		 */
		let struct2: TypeRef = Type::Struct(Struct::new_with_id(
			&[
				("length".into(), Type::Uint32T.into()),
				("buffer".into(), array1.clone()),
			],
			2
		)).into();
		let struct_def: TypeDefinition = (&struct2).into();
		code_block.push(struct_def.into());

		/*
		 * Map 0: Define the type that the perf buf would take
		 */
		let map0: TypeRef = Type::BpfMap(BpfMap::PerfEventArray(
			PerfEventArray::new_with_id(
				ScalarValue::Const("sizeof(int)".into()),
				ScalarValue::Const("sizeof(int)".into()),
				0
			)
		)).into();
		let map_def: TypeDefinition = (&map0).into();
		code_block.push(map_def.into());

		/*
		 * perf_buf: Define the actual perf buffer
		 */
		let perf_buf: VariableRef = Variable::new_with_id(map0.clone(), None, 0).into();
		let perf_buf_def: VariableDefinition = (&perf_buf).into();
		code_block.push(perf_buf_def.into());

		/*
		 * Define the type that the buffer map would take
		 */
		let key: TypeRef = Type::__U32.into();
		let value = struct2.clone();
		let buffer_map_t: TypeRef = Type::BpfMap(BpfMap::PerCpuArray(
			PerCpuArray::new_with_id(key,value, 1, 0)
		)).into();
		let buffer_map_def: TypeDefinition = (&buffer_map_t).into();
		code_block.push(buffer_map_def.into());

		/*
		 * Define an instance of the buffer map
		 */
		let buffer_map: VariableRef =
			Variable::new_with_id(buffer_map_t.clone(), None, 1).into();
		let buffer_map_def: VariableDefinition = (&buffer_map).into();
		code_block.push(buffer_map_def.into());

		/*
		 * Define the BPF program
		 */

		let ret: TypeRef = Type::Int.into();
		let args: Vec<TypeRef> = vec![sys_enter_ctx.clone()];
		let bpf_declaration = FunctionDeclaration::new(ret, args);
		let mut bpf_scope_block = ScopeBlock::new();

		let task_struct_t: TypeRef =
			Type::Other("struct task_struct".into()).into();

		let task_struct_ptr_t: TypeRef =
			Type::Pointer(Pointer::new(task_struct_t).into()).into();

		let task: VariableRef =
			Variable::new(task_struct_ptr_t.clone(), None).into();
		let task_def: VariableDefinition = (&task).into();
		bpf_scope_block.push(task_def.into());

		let bpf_get_current_task: FunctionRef =
			Function::with_name("bpf_get_current_task").into();

		let bpf_get_current_task_call: Expr =
			FunctionCall::new(bpf_get_current_task.clone(), Vec::new()).into();

		let task_assign: VariableAssignment = 
			VariableAssignment::new(task.clone(), bpf_get_current_task_call);
		bpf_scope_block.push(task_assign.into());


		let pid: VariableRef = Variable::new(Type::Uint32T.into(), None).into();
		let pid_definition: VariableDefinition = (&pid).into();
		let pid_assignment: VariableAssignment = 
			VariableAssignment::new(pid.clone(), ScalarValue::Uint(0).into());
		bpf_scope_block.push(pid_definition.into());
		bpf_scope_block.push(pid_assignment.into());

		let tid: VariableRef = Variable::new(Type::Uint32T.into(), None).into();
		let tid_definition: VariableDefinition = (&tid).into();
		let tid_assignment: VariableAssignment = 
			VariableAssignment::new(tid.clone(), ScalarValue::Uint(0).into());
		bpf_scope_block.push(tid_definition.into());
		bpf_scope_block.push(tid_assignment.into());

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
