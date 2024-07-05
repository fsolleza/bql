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
			Self::Int => "int;".into(),
			Self::Char => "char;".into(),
			Self::Void => "void;".into(),
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
		format!("{} *;", self.typ.gen_signature())
	}
}

/// Represents a C expression that returns a value (can return void)
pub enum Expr {
	ScalarValue(ScalarValue),
	Variable(Variable),
	Arithmetic(Box<Arithmetic>),
	Comparison(Box<Comparison>),
	FunctionCall(Box<FunctionCall>),
}

pub enum ArithmeticOperator {
	Add,
	Sub,
}

pub struct Arithmetic {
	left: Expr,
	right: Expr,
	op: ArithmeticOperator,
}

pub struct Comparison {
	left: Expr,
	right: Expr,
	op: ComparisonOperator,
}

pub enum ComparisonOperator {
	Eq,
	NotEq,
}

pub struct FunctionCall {
	func: Function,
	args: Vec<Expr>,
}

pub enum CodeUnit {
	TypeDefinition(TypeRef),
	VariableDefinition(VariableRef),
	Assignment(Assignment),
	Expr(Expr),
	If(IfBlock),
}

pub struct IfBlock {
	expr: Expr,
	block: CodeBlock,
}

pub struct CodeBlock {
	lines: Vec<CodeUnit>,
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

pub struct Assignment {}

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
		format!("{} var_{};", self.typ.gen_signature(), self.id)
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
		format!("typedef {} ArrType_{}[{}];",
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

		s.push_str(&format!("}} struct_{};\n", self.id));
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
