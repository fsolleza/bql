use rand::prelude::*;
use std::sync::Arc;

pub enum ScalarValue {
	Null,
	Float(f64),
	UInt(u64),
	Bool(bool),
	Int(i64),
	CString(String),
}

impl ScalarValue {
	fn gen_expression(&self) -> String {
		match self {
			Self::Null => "null".into(),
			Self::Float(x) => format!("{}", x),
			Self::UInt(x) => format!("{}", x),
			Self::Bool(x) => format!("{}", x),
			Self::Int(x) => format!("{}", x),
			Self::CString(x) => x.clone(),
		}
	}
}

#[derive(Clone)]
pub enum Type {
	Void,
	Int,
	Char,
	Struct(Struct),
	Array(Array),
	Pointer(Pointer),
}

// Types can be referenced / used / initialized many times
type TypeRef = Arc<Type>;

impl Type {
	pub fn gen_signature(&self) -> String {
		match self {
			Self::Int => "int".into(),
			Self::Char => "char".into(),
			Self::Void => "void".into(),
			Self::Struct(s) => s.gen_signature(),
			Self::Array(a) => a.gen_signature(),
			Self::Pointer(p) => p.gen_signature(),
		}
	}

	pub fn gen_definition(&self) -> String {
		match self {
			Self::Int => "int".into(),
			Self::Char => "char".into(),
			Self::Void => "void".into(),
			Self::Struct(s) => s.gen_definition(),
			Self::Array(a) => a.gen_definition(),
			Self::Pointer(p) => p.gen_definition(),
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
	Variable(Variable),
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
		}
	}

	pub fn gen_code_unit(&self) -> String {
		let mut s = self.gen_expression();
		s.push_str(";\n");
		s
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
	pub fn gen_expression(&self) -> String {
		self.func.gen_call(&self.args)
	}
}

pub struct FunctionDefinition {
	func: FunctionRef,
}

impl FunctionDefinition {
	pub fn new(
		name: &str,
		decl: FunctionDeclaration,
		def: CodeBlock,
	) -> Self {
		let func = Function::from_parts(name, Some(decl), Some(def)).into();
		Self { func }
	}

	pub fn get_function_ref(&self) -> FunctionRef {
		self.func.clone()
	}

	pub fn gen_code_unit(&self) -> String {
		self.func.gen_definition().unwrap()
	}
}

pub enum CodeUnit {
	TypeDefinition(TypeDefinition),
	VariableDefinition(VariableDefinition),
	FunctionDefinition(FunctionDefinition),
	Assignment(Assignment),
	Expr(Expr),
	If(IfBlock),
}

impl CodeUnit {
	pub fn gen_code_unit(&self) -> String {
		match self {
			Self::TypeDefinition(x) => x.gen_code_unit(),
			Self::VariableDefinition(x) => x.gen_code_unit(),
			Self::FunctionDefinition(x) => x.gen_code_unit(),
			Self::Assignment(x) => x.gen_code_unit(),
			Self::Expr(x) => x.gen_code_unit(),
			Self::If(x) => x.gen_code_unit(),
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

pub struct IfBlock {
	expr: VariableRef,
	block: CodeBlock,
}

impl IfBlock {
	pub fn from_parts(expr: VariableRef, block: CodeBlock) -> Self {
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

pub struct CodeBlock {
	units: Vec<CodeUnit>,
}

impl CodeBlock {
	pub fn new() -> Self {
		CodeBlock { units: Vec::new() }
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
}

struct FunctionDeclaration {
	ret: TypeRef,
	args: Vec<TypeRef>,
}

pub struct Function {
	name: String,
	declaration: Option<FunctionDeclaration>,
	definition: Option<CodeBlock>,
}

// Functions can be referenced / called many times
type FunctionRef = Arc<Function>; 

impl Function {
	pub fn with_name(name: &str) -> Self {
		Self::from_parts(name, None, None)
	}

	pub fn from_parts(
		name: &str,
		declaration: Option<FunctionDeclaration>,
		definition: Option<CodeBlock>
	) -> Self {
		Self { name: name.into(), declaration, definition }
	}

	pub fn gen_declaration(&self) -> Option<String> {
		let decl = self.declaration.as_ref()?;
		let mut args = String::new();
		for (i, arg) in decl.args.iter().enumerate() {
			args.push_str(&arg.gen_signature());
			args.push_str(&format!(" arg_{}", i));
			if i < decl.args.len() {
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

pub struct Assignment {
	variable: VariableRef,
	expr: Expr,
}

impl Assignment {
	pub fn new(variable: VariableRef, expr: Expr) -> Self {
		Self { variable, expr, }
	}

	pub fn gen_code_unit(&self) -> String {
		format!("{} = {};\n",
				self.variable.gen_expression(),
				self.expr.gen_expression())
	}
}

#[derive(Clone)]
pub struct Variable {
	typ: TypeRef,
	id: u64,
}

// Variables can be used or referenced or assigned to multiple times
type VariableRef = Arc<Variable>;

impl Variable {
	pub fn new(typ: TypeRef) -> Self {
		let id = thread_rng().gen();
		Self::new_with_id(typ, id)
	}

	pub fn new_with_id(typ: TypeRef, id: u64) -> Self {
		Self { typ, id }
	}

	pub fn gen_definition(&self) -> String {
		format!("{} var_{}", self.typ.gen_signature(), self.id)
	}

	pub fn gen_expression(&self) -> String {
		format!("var_{}", self.id)
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
			s.push_str(&format!("\t{} {};\n", name, typ.gen_signature()));
		}

		s.push_str(&format!("}} struct_{}\n", self.id));
		s
	}

}

#[cfg(test)]
mod test {
	use super::*;

	fn remove_whitespace(s: &str) -> String {
		s.chars().filter(|c| !c.is_whitespace()).collect()
	}

	fn assert_code_eq(l: &str, r: &str) {
		assert_eq!(remove_whitespace(l), remove_whitespace(r));
	}

	#[test]
	fn array_def1() {
		let exp = "typedef char ArrType_1[3];";
		let arr = Type::new_array_with_id(Type::Char.into(), 3, 1);
		assert_code_eq(exp, &arr.gen_definition());
	}

	#[test]
	fn array_def2() {
		let exp = "typedef struct_0 ArrType_1[3];";

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
			} struct_0;
		";
		let arr = Type::new_array_with_id(Type::Int.into(), 5, 1).into();
		let fields = [
			("field1".into(), Type::Int.into()),
			("field2".into(), arr)
		];
		let s = Type::new_struct_with_id(&fields, 0);
		assert_code_eq(exp, &s.gen_definition());
	}
}
