use std::collections::HashSet;

use std::ops::{Add, Deref, DerefMut, Mul};

pub fn add_scalar<T: Copy + Add<Output = T>>(data: &mut [T], val: T) {
	for i in 0..data.len() {
		data[i] = data[i] + val;
	}
}

pub fn add_slice<T: Copy + Add<Output = T>>(data: &mut [T], other: &[T]) {
	for i in 0..data.len() {
		data[i] = data[i] + other[i];
	}
}

pub fn mul_scalar<T: Copy + Mul<Output = T>>(data: &mut [T], val: T) {
	for i in 0..data.len() {
		data[i] = data[i] * val;
	}
}

pub fn mul_slice<T: Copy + Mul<Output = T>>(data: &mut [T], other: &[T]) {
	for i in 0..data.len() {
		data[i] = data[i] * other[i];
	}
}

pub fn eq_scalar<T: Copy + Eq + PartialEq>(
	data: &[T],
	val: T,
	results: &mut [bool],
) {
	for i in 0..data.len() {
		results[i] &= data[i] == val;
	}
}

pub fn eq_slice<T: Copy + Eq + PartialEq>(
	data: &[T],
	other: &[T],
	results: &mut [bool],
) {
	for i in 0..data.len() {
		results[i] &= data[i] == other[i];
	}
}

use crate::user_plan::{Column, UserScalar, Batch};

enum IntSlice {
	U64(Vec<u64>),
	I64(Vec<i64>),
}

impl IntSlice {
	pub fn len(&self) -> usize {
		match self {
			Self::U64(x) => x.len(),
			Self::I64(x) => x.len(),
		}
	}

	fn add_slice(mut self, other: IntSlice) -> Self {
		match (&mut self, other) {
			(Self::U64(ref mut l), Self::U64(r)) => {
				add_slice(l, &r);
				self
			}
			(Self::I64(ref mut l), Self::I64(r)) => {
				add_slice(l, &r);
				self
			}
			// Handled at the planning level
			_ => unreachable!(),
		}
	}

	fn add_scalar(mut self, scalar: &UserScalar) -> Self {
		match (&mut self, scalar) {
			(Self::U64(ref mut l), UserScalar::U64(r)) => {
				add_scalar(l, *r);
				self
			}
			(Self::I64(ref mut l), UserScalar::I64(r)) => {
				add_scalar(l, *r);
				self
			}
			// Handled at the planning level
			_ => unreachable!(),
		}
	}

	fn mul_slice(mut self, other: IntSlice) -> Self {
		match (&mut self, other) {
			(Self::U64(ref mut l), Self::U64(r)) => {
				mul_slice(l, &r);
				self
			}
			(Self::I64(ref mut l), Self::I64(r)) => {
				mul_slice(l, &r);
				self
			}
			// Handled at the planning level
			_ => unreachable!(),
		}
	}

	fn mul_scalar(mut self, scalar: &UserScalar) -> Self {
		match (&mut self, scalar) {
			(Self::U64(ref mut l), UserScalar::U64(r)) => {
				mul_scalar(l, *r);
				self
			}
			(Self::I64(ref mut l), UserScalar::I64(r)) => {
				mul_scalar(l, *r);
				self
			}
			// Handled at the planning level
			_ => unreachable!(),
		}
	}
}

impl From<Column> for IntSlice {
	fn from(item: Column) -> Self {
		match item {
			Column::U64(x) => IntSlice::U64(x[..].into()),
			Column::I64(x) => IntSlice::I64(x[..].into()),
		}
	}
}

impl From<&Column> for IntSlice {
	fn from(item: &Column) -> Self {
		match item {
			Column::U64(x) => IntSlice::U64(x[..].into()),
			Column::I64(x) => IntSlice::I64(x[..].into()),
		}
	}
}

impl From<&mut Column> for IntSlice {
	fn from(item: &mut Column) -> Self {
		match item {
			Column::U64(x) => IntSlice::U64(x[..].into()),
			Column::I64(x) => IntSlice::I64(x[..].into()),
		}
	}
}

pub enum TransformOp {
	AddScalar(Box<TransformOp>, UserScalar),
	AddSlice(Box<TransformOp>, Box<TransformOp>),
	MulScalar(Box<TransformOp>, UserScalar),
	MulSlice(Box<TransformOp>, Box<TransformOp>),
	Init(String),
}

impl TransformOp {
	fn execute(&self, batch: &Batch) -> IntSlice {
		match self {
			Self::Init(x) => {
				batch.get_column(&x).unwrap().into()
			},

			Self::AddScalar(l, r) => {
				let l = l.execute(batch);
				l.add_scalar(r)
			}

			Self::AddSlice(l, r) => {
				let l = l.execute(batch);
				let r = r.execute(batch);
				l.add_slice(r)
			}

			Self::MulScalar(l, r) => {
				let l = l.execute(batch);
				l.mul_scalar(r)
			}

			Self::MulSlice(l, r) => {
				let l = l.execute(batch);
				let r = r.execute(batch);
				l.mul_slice(r)
			}

			_ => unimplemented!(),
		}
	}
}

fn column_eq_column(l: &Column, r: &Column, result: &mut [bool]) {
	match (l, r) {
		(Column::U64(l), Column::U64(r)) => eq_slice(&l, &r, result),
		(Column::I64(l), Column::I64(r)) => eq_slice(&l, &r, result),
		// Handled at the planning level
		_ => unreachable!(),
	}
}

fn column_eq_scalar(l: &Column, r: &UserScalar, result: &mut [bool]) {
	match (l, r) {
		(Column::U64(l), UserScalar::U64(r)) => eq_scalar(&l, *r, result),
		(Column::I64(l), UserScalar::I64(r)) => eq_scalar(&l, *r, result),
		// Handled at the planning level
		_ => unreachable!(),
	}
}

fn column_eq_intslice(l: &Column, r: &IntSlice, result: &mut [bool]) {
	match (l, r) {
		(Column::U64(l), IntSlice::U64(r)) => eq_slice(&l, &r, result),
		(Column::I64(l), IntSlice::I64(r)) => eq_slice(&l, &r, result),
		// Handled at the planning level
		_ => unreachable!(),
	}
}

fn intslice_eq_scalar(l: &IntSlice, r: &UserScalar, result: &mut [bool]) {
	match (l, r) {
		(IntSlice::U64(l), UserScalar::U64(r)) => eq_scalar(&l, *r, result),
		(IntSlice::I64(l), UserScalar::I64(r)) => eq_scalar(&l, *r, result),
		// Handled at the planning level
		_ => unreachable!(),
	}
}

fn intslice_eq_intslice(l: &IntSlice, r: &IntSlice, result: &mut [bool]) {
	match (l, r) {
		(IntSlice::U64(l), IntSlice::U64(r)) => eq_slice(&l, &r, result),
		(IntSlice::I64(l), IntSlice::I64(r)) => eq_slice(&l, &r, result),
		// Handled at the planning level
		_ => unreachable!(),
	}
}

pub struct CompareResult {
	set: Vec<bool>,
}

impl CompareResult {
	pub fn len(&self) -> usize {
		self.set.len()
	}

	pub fn into_vec(self) -> Vec<bool> {
		self.set
	}
}

impl Deref for CompareResult {
	type Target = Vec<bool>;
	fn deref(&self) -> &Self::Target {
		&self.set
	}
}

impl DerefMut for CompareResult {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.set
	}
}

pub enum CompareOp {
	ColumnEqColumn(Column, Column),
	ColumnEqTransform(Column, TransformOp),
	ColumnEqScalar(Column, UserScalar),
	TransformEqScalar(TransformOp, UserScalar),
	TransformEqTransform(TransformOp, TransformOp),
	And(Box<CompareOp>, Box<CompareOp>),
}

impl CompareOp {
	pub fn execute(&mut self, batch: &Batch) -> CompareResult {
		match self {
			Self::ColumnEqColumn(l, r) => {
				let mut result: Vec<bool> = vec![true; batch.len()];
				column_eq_column(l, r, &mut result);
				CompareResult { set: result }
			}

			Self::ColumnEqScalar(l, r) => {
				let mut result: Vec<bool> = vec![true; batch.len()];
				column_eq_scalar(l, r, &mut result);
				CompareResult { set: result }
			}

			Self::ColumnEqTransform(l, r) => {
				let mut result: Vec<bool> = vec![true; batch.len()];
				let r = r.execute(batch);
				column_eq_intslice(l, &r, &mut result);
				CompareResult { set: result }
			}

			Self::TransformEqScalar(l, r) => {
				let mut result: Vec<bool> = vec![true; batch.len()];
				let l = l.execute(batch);
				intslice_eq_scalar(&l, &r, &mut result);
				CompareResult { set: result }
			}

			Self::TransformEqTransform(l, r) => {
				let mut result: Vec<bool> = vec![true; batch.len()];
				let l = l.execute(batch);
				let r = r.execute(batch);
				intslice_eq_intslice(&l, &r, &mut result);
				CompareResult { set: result }
			}

			Self::And(l, r) => {
				let mut l = l.execute(batch);
				let r = r.execute(batch);
				for i in 0..l.len() {
					l[i] &= r[i];
				}
				l
			}
		}
	}
}
