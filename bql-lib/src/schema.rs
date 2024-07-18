pub SchemaKind {
	U64(Option<u64>),
	I64(Option<i64>),
	U32(Option<u32>),
	I32(Option<u32>),
	Array(Option<SchemaArray>),
	String(Option<usize>),
}

impl SchemaKind {
	pub const fn size(&self) -> usize {
		Self::u64(_) => 8,
		Self::i64(_) => 8,
		Self::u32(_) => 4,
		Self::i32(_) => 4,
		Self::Array(_) => 4,
	}
}

pub SchemaArray {
	kind: Box<SchemaKind>,
	len: usize,
}

