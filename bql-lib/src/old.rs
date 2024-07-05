#[derive(Eq, PartialEq)]
pub enum BQLType {
	U64,
	F64,
}

pub enum BQLValue {
	U64(u64),
	F64(f64),
	Field(String),
}

impl BQLValue {
	pub fn bql_type(&self) -> BQLType {
		match self {
			Self::U64(_) => BQLType::U64,
			Self::F64(_) => BQLType::F64
		}
	}
}

pub struct Context {
	ctx: String,
	label: String,
}

impl Context {
	pub fn new(ctx: String, label: String) -> Self {
		Self { ctx, label }
	}
}

pub struct Select {
	fields: Vec<String>
}

impl Select {
	pub fn new(fields: Vec<String>) -> Self {
		Self { fields }
	}
}


pub struct Filter {
	inner: Vec<Comparison>,
}

impl Filter {
	pub fn new(left: BQLValue, right: BQLValue, op: CompareOp) -> Option<Self> {
		let mut inner = Vec::new();
		inner.push(Comparison::new(left, right, op, None)?);
		Some(Self { inner })
	}

	pub fn and(
		&mut self,
		left: BQLValue,
		right: BQLValue,
		op: CompareOp
	) -> Option<&mut Self> {
		let f = Comparison::new(left, right, op, Some(Conjunction::AND))?;
		self.inner.push(f);
		Some(self)
	}

	pub fn or(
		&mut self,
		left: BQLValue,
		right: BQLValue,
		op: CompareOp
	) -> Option<&mut Self> {
		let f = Comparison::new(left, right, op, Some(Conjunction::OR))?;
		self.inner.push(f);
		Some(self)
	}
}

struct Comparison {
	conjunction: Option<Conjunction>,
	left: BQLValue,
	right: BQLValue,
	op: CompareOp,
}

impl Comparison {
	fn new(
		left: BQLValue,
		right: BQLValue,
		op: CompareOp,
		conjunction: Option<Conjunction>
	) -> Option<Self> {
		if left.bql_type() == right.bql_type() {
			let filter = Self { conjunction, left, right, op };
			Some(filter)
		} else {
			None
		}
	}
}

enum CompareOp {
	LT,
	GT,
	EQ,
}

enum Conjunction {
	AND,
	OR,
}

struct Join {
	quries: Vec<Query>,
	on: Comparison,
}

enum InnerQuery {
	Join(Join),
	Query {
		ctx: Context,
		select: Select,
		filter: Option<Filter>,
	},
}
