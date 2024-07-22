use crate::bpf::BpfObject;
use crate::codegen::Kind;
use crate::schema::*;
use crossbeam::channel::{bounded, Receiver, Sender};
use libbpf_rs::{Map, PerfBufferBuilder};
use std::collections::HashMap;
use std::ops::Deref;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub enum Column {
	u64(Vec<u64>),
	i64(Vec<i64>),
}

impl Column {
	pub fn from_schema_kind(kind: &SchemaKind) -> Self {
		match kind {
			SchemaKind::u64 => Self::u64(Vec::new()),
			SchemaKind::i64 => Self::i64(Vec::new()),
		}
	}

	pub fn push_bytes(&mut self, bytes: &[u8]) {
		match self {
			Self::u64(x) => {
				x.push(u64::from_ne_bytes(bytes.try_into().unwrap()))
			}
			Self::i64(x) => {
				x.push(i64::from_ne_bytes(bytes.try_into().unwrap()))
			}
		}
	}
}

#[derive(Debug)]
pub struct Batch {
	columns: HashMap<String, Column>,
}

impl Batch {
	fn from_schema(schema: &Schema) -> Self {
		let mut batch = Batch {
			columns: HashMap::new(),
		};
		for (name, kind) in schema.iter() {
			batch
				.columns
				.insert(name.into(), Column::from_schema_kind(kind));
		}
		batch
	}

	fn get_column_mut(&mut self, name: &str) -> Option<&mut Column> {
		self.columns.get_mut(name)
	}
}

pub struct UserPlan {
	object: BpfObject,
	root: Box<Operator>,
}

impl UserPlan {
	pub fn execute(&mut self) {
		self.object.attach_programs();
		// Call next until no more batches
		while let Some(batch) = self.root.next_batch() { }
	}

	pub fn new(object: BpfObject, root: Operator) -> Self {
		Self {
			object,
			root: Box::new(root)
		}
	}
}

pub enum Operator {
	ReadFromPerfEventArray(ReadFromPerfEventArray),
	Noop(Noop),
	PrintData(PrintData),
}

impl Operator {
	pub fn next_batch(&mut self) -> Option<Batch> {
		match self {
			Operator::ReadFromPerfEventArray(x) => x.next_batch(),
			Operator::Noop(x) => x.next_batch(),
			Operator::PrintData(x) => x.next_batch(),
		}
	}
}

pub struct PrintData {
	source: Box<Operator>,
}

impl PrintData {

	pub fn new(source: Operator) -> Self {
		Self { source: Box::new(source) }
	}

	pub fn to_op(self) -> Operator {
		Operator::PrintData(self)
	}
	pub fn next_batch(&mut self) -> Option<Batch> {
		let batch = self.source.next_batch()?;
		println!("{:?}", batch);
		Some(batch)
	}
}

pub struct Noop {
	source: Box<Operator>,
}

impl Noop {
	pub fn to_op(self) -> Operator {
		Operator::Noop(self)
	}
	pub fn next_batch(&mut self) -> Option<Batch> {
		let batch = self.source.next_batch()?;

		// Do something with batch but in this op, nothing
		Some(batch)
	}
}

pub struct ReadFromPerfEventArray {
	rx: Receiver<Batch>,
	tx: Sender<Batch>,
}

impl ReadFromPerfEventArray {
	pub fn to_op(self) -> Operator {
		Operator::ReadFromPerfEventArray(self)
	}

	pub fn next_batch(&mut self) -> Option<Batch> {
		Some(self.rx.recv().unwrap())
	}

	pub fn new(
		map: &mut Map,
		item_t: &Kind,
		buffer_t: &Kind,
		schema: &Schema,
	) -> Self {
		let (tx, rx) = bounded(256);

		let item_t = item_t.clone();
		let buffer_t = buffer_t.clone();
		let schema = schema.clone();

		let tx_clone = tx.clone();
		let perf_buffer = PerfBufferBuilder::new(map)
			.sample_cb(move |cpu: i32, bytes: &[u8]| {
				let batch = read_batch(&buffer_t, &item_t, bytes, &schema);
				tx_clone.send(batch).unwrap();
			})
			.lost_cb(move |cpu: i32, count: u64| {
				eprintln!("Lost {count} events on CPU {cpu}");
			})
			.build()
			.unwrap();

		thread::spawn(move || {
			println!("Polling");
			loop {
				perf_buffer.poll(Duration::from_secs(10)).unwrap();
			}
		});
		Self { rx, tx }
	}
}

fn read_batch(
	buffer_t: &Kind,
	item_t: &Kind,
	data: &[u8],
	schema: &Schema,
) -> Batch {
	let buffer_fields = buffer_t.as_cstruct_ref().unwrap().read_fields(data);

	// NOTE:
	// TODO:
	// This interface depends on how buffer is laid out in
	// kernel_plan::KernelBpfMap::per_cpu_buffer
	let mut len: u32 = 0;
	let mut data: &[u8] = &[0u8];

	for (field, bytes) in buffer_fields.iter() {
		if field == &"length" {
			len = u32::from_ne_bytes((*bytes).try_into().unwrap());
		}
		if field == &"buffer" {
			data = bytes;
		}
	}

	let mut batch = Batch::from_schema(&schema);
	let mut offset = 0;
	for i in 0..len {
		let d = &data[offset..];
		let item_fields = item_t.as_cstruct_ref().unwrap().read_fields(d);
		for (field, bytes) in item_fields {
			batch.get_column_mut(field).unwrap().push_bytes(bytes);
			offset += bytes.len();
		}
	}

	batch
}

pub struct PerfEventItem {
	pub cpu: i32,
	pub batch: Batch,
}
