use std::{ops::Deref, sync::Arc};

#[derive(Clone)]
pub enum SchemaKind {
	u64,
	i64,
}

#[derive(Clone)]
pub struct Schema {
	inner: Arc<Vec<(String, SchemaKind)>>,
}

pub struct SchemaBuilder {
	inner: Vec<(String, SchemaKind)>
}

impl SchemaBuilder {
	pub fn new() -> Self {
		Self {
			inner: Vec::new(),
		}
	}

	pub fn add_field(&mut self, s: &str, k: SchemaKind) -> &mut Self {
		self.inner.push((s.into(), k));
		self
	}

	pub fn build(&self) -> Schema {
		Schema { inner: self.inner.clone().into() }
	}
}

impl std::ops::Deref for Schema {
	type Target = [(String, SchemaKind)];
	fn deref(&self) -> &Self::Target {
		self.inner.as_slice()
	}
}
