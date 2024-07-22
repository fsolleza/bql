pub SchemaKind {
	U64,
	I64,
	U32,
	I32,
}

pub SchemaField {
	name: String,
	value: SchemaKind,
}

pub struct Schema {
	inner: Vec<SchemaField>,
}

