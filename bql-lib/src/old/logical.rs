use crate::common::*;
use std::sync::Arc;

pub enum Expr {
	Attribute(Attribute),
	Struct(Struct),
	Literal(ScalarValue),
	BinaryExpr(BinaryExpr),
	GroupBy(GroupBy),
	Context(Context),
}

pub enum BinaryOperator {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

pub struct BinaryExpr {
	pub left: Box<Expr>,
	pub right: Box<Expr>,
	pub op: BinaryOperator,
}

pub struct GroupBy { }
pub struct Context { }
pub struct Attribute { }
pub struct Struct { }

/// Logical operator that represents a BPF event happening and emits an empty
/// tuple.  All LogicalPlans start with one or more events.
pub struct Event { }

/// Logical operator that projects attribtues of a tuple and emits the tuple
/// with just those attributes
pub struct Project { }

/// Logical operator that appends an attribute to a tuple from an available
/// Struct in the context or a scalar. Emits
pub struct Append { }

/// Logical operator that determines whether to emit a tuple or not based on
/// some rule.
pub struct Filter { }

pub struct Aggregate { }  // Aggregate tuples by the given window

pub enum LogicalOperator {
	Event(Event),
	Project(Project),
	Filter(Filter),
	Aggregate(Aggregate),
	Sink,
}

pub struct LogicalPlan {
	operator: LogicalOperator,
	next: Arc<LogicalPlan>,
}
