use crate::bpf::BpfObject;
use crate::codegen::Kind;
use crate::schema::*;
use crate::user_plan_helpers::*;
use crossbeam::channel::{bounded, unbounded, Receiver, Sender};
use libbpf_rs::{Map, MapHandle, MapFlags, PerfBufferBuilder};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub enum Scalar {
	U64(u64),
	I64(i64),
}

pub type UserScalar = Scalar;

#[derive(Debug, Clone)]
pub enum Column {
	U64(Arc<[u64]>),
	I64(Arc<[i64]>),
}

impl Column {
	pub fn len(&self) -> usize {
		match self {
			Self::U64(x) => x.len(),
			Self::I64(x) => x.len(),
		}
	}

	pub fn as_slice_u64(&self) -> Option<&[u64]> {
		match self {
			Self::U64(x) => Some(&x[..]),
			_ => None,
		}
	}

	pub fn as_slice_i64(&self) -> Option<&[i64]> {
		match self {
			Self::I64(x) => Some(&x[..]),
			_ => None,
		}
	}
}

enum ColumnBuilder {
	u64(Vec<u64>),
	i64(Vec<i64>),
}

impl ColumnBuilder {
	fn from_schema_kind(kind: &SchemaKind) -> Self {
		match kind {
			SchemaKind::u64 => Self::u64(Vec::new()),
			SchemaKind::i64 => Self::i64(Vec::new()),
		}
	}

	fn push_bytes(&mut self, bytes: &[u8]) {
		match self {
			Self::u64(x) => {
				x.push(u64::from_ne_bytes(bytes.try_into().unwrap()))
			}
			Self::i64(x) => {
				x.push(i64::from_ne_bytes(bytes.try_into().unwrap()))
			}
		}
	}

	fn build(self) -> Column {
		match self {
			Self::u64(x) => Column::U64(x.into()),
			Self::i64(x) => Column::I64(x.into()),
		}
	}

	fn len(&self) -> usize {
		match self {
			Self::u64(x) => x.len(),
			Self::i64(x) => x.len(),
		}
	}
}

struct BatchBuilder {
	columns: Vec<(String, ColumnBuilder)>,
	len: usize,
}

impl BatchBuilder {
	fn get_column_mut(&mut self, name: &str) -> Option<&mut ColumnBuilder> {
		for (k, v)  in self.columns.iter_mut() {
			if k == name {
				return Some(v);
			}
		}
		None
	}

	fn from_schema(schema: &Schema) -> Self {
		let mut batch = BatchBuilder {
			columns: Vec::new(),
			len: 0,
		};
		for (name, kind) in schema.iter() {
			batch
				.columns
				.push((name.into(), ColumnBuilder::from_schema_kind(kind)));
		}
		batch
	}

	fn build(self) -> Batch {
		let mut columns = Vec::new();
		for (k, v) in self.columns {
			assert_eq!(v.len(), self.len);
			columns.push((k, v.build()));
		}
		let include = vec![true; self.len];

		Batch {
			columns,
			include,
			len: self.len,
		}
	}
}

#[derive(Debug, Clone)]
pub struct Batch {
	columns: Vec<(String, Column)>,
	include: Vec<bool>,
	len: usize,
}

impl Batch {

	pub fn as_pretty_string(&self) -> String {
		use std::fmt::Write;
		let mut s = String::new();
		for i in 0..self.include.len() {
			if self.include[i] {
				for (name, column) in self.columns.iter() {
					match column {
						Column::U64(x) => {
							write!(&mut s, "{}: {}, ", name, x[i]).unwrap();
						},
						Column::I64(x) => {
							write!(&mut s, "{}: {}, ", name, x[i]).unwrap();
						},
					}
				}
			}
			write!(&mut s, "\n");
		}
		s
	}

	pub fn get_column(&self, name: &str) -> Option<Column> {
		for (k, v) in self.columns.iter() {
			if k == name {
				return Some(v.clone())
			}
		}
		None
	}

	pub fn len(&self) -> usize {
		self.len
	}

	pub fn include_count(&self) -> usize {
		let mut count = 0;
		for i in self.include.iter() {
			if *i {
				count += 1;
			}
		}
		count
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
		while let Some(batch) = self.root.next_batch() {}
	}

	pub fn new(object: BpfObject, root: Operator) -> Self {
		Self {
			object,
			root: Box::new(root),
		}
	}
}

pub enum Operator {
	ReadFromPerfEventArray(ReadFromPerfEventArray),
	ReadCountFromPerCpuHash(ReadCountFromPerCpuHash),
	Noop(Noop),
	PrintData(PrintData),
	Select(Select),
	SinkData(SinkData),
}

impl Operator {
	pub fn next_batch(&mut self) -> Option<Batch> {
		match self {
			Operator::ReadCountFromPerCpuHash(x) => x.next_batch(),
			Operator::ReadFromPerfEventArray(x) => x.next_batch(),
			Operator::Noop(x) => x.next_batch(),
			Operator::PrintData(x) => x.next_batch(),
			Operator::Select(x) => x.next_batch(),
			Operator::SinkData(x) => x.next_batch(),
		}
	}
}

pub struct Select {
	op: CompareOp,
	source: Box<Operator>,
}

impl Select {
	pub fn new(op: CompareOp, source: Operator) -> Self {
		Self {
			op,
			source: Box::new(source),
		}
	}

	pub fn to_op(self) -> Operator {
		Operator::Select(self)
	}

	pub fn next_batch(&mut self) -> Option<Batch> {
		let mut batch = self.source.next_batch()?;
		let filter_result = self.op.execute(&batch);
		// merge filters
		for i in 0..filter_result.len() {
			batch.include[i] &= filter_result[i];
		}
		Some(batch)
	}
}

pub struct ColumnMap {
	source: Box<Operator>,
	column: String,
}

pub struct SinkData {
	source: Box<Operator>,
	sender: Sender<Batch>,
	receiver: Receiver<Batch>,
}

impl SinkData {
	pub fn new(source: Operator) -> Self {
		let (tx, rx) = bounded(256);
		Self {
			source: Box::new(source),
			sender: tx,
			receiver: rx,
		}
	}

	pub fn to_op(self) -> Operator {
		Operator::SinkData(self)
	}

	pub fn receiver(&self) -> Receiver<Batch> {
		self.receiver.clone()
	}

	pub fn next_batch(&mut self) -> Option<Batch> {
		let batch = self.source.next_batch()?;
		self.sender.try_send(batch.clone()).unwrap();
		Some(batch)
	}
}

pub struct PrintData {
	source: Box<Operator>,
}

impl PrintData {
	pub fn new(source: Operator) -> Self {
		Self {
			source: Box::new(source),
		}
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

fn read_count_percpu_hash(map: MapHandle, interval: Duration, tx: Sender<Batch>) {
	let mut last_count = HashMap::new();
	loop {
		thread::sleep(Duration::from_secs(1));
		let now = SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap()
			.as_micros() as u64;
		let mut tmp_vec = Vec::new();
		for k in map.keys() {
			let read_values: Vec<Vec<u8>> =
				map.lookup_percpu(&k, MapFlags::ANY).unwrap().unwrap();
			let mut value = 0;
			for read_value in read_values {
				value += u64::from_ne_bytes(read_value.try_into().unwrap());
			}
			let key = u64::from_ne_bytes(k.try_into().unwrap());
			let last_value = last_count.entry(key).or_insert(0);
			if value > *last_value {
				tmp_vec.push((key, value - *last_value));
				*last_value = value;
			}
		}

		let len = tmp_vec.len();
		let mut time_vec = Vec::new();
		let mut key_vec = Vec::new();
		let mut value_vec = Vec::new();

		for (k, v) in tmp_vec {
			time_vec.push(now);
			key_vec.push(k);
			value_vec.push(v);
		}

		let mut columns: Vec<(String, Column)> = Vec::new();
		columns.push(("time".into(), Column::U64(time_vec.into())));
		columns.push(("system_call".into(), Column::U64(key_vec.into())));
		columns.push(("count".into(), Column::U64(value_vec.into())));

		let batch = Batch {
			columns,
			include: vec![true; len],
			len,
		};
		tx.send(batch).unwrap();
	}
}

struct PerCpuHash {
	map: Map
}

/*
 * Safety: This is only used in one thread and is read every Duration
 */
unsafe impl Send for PerCpuHash {}
unsafe impl Sync for PerCpuHash {}

pub struct ReadCountFromPerCpuHash {
	rx: Receiver<Batch>,
	tx: Sender<Batch>,
}

impl ReadCountFromPerCpuHash {
	pub fn new(map: &Map, interval: Duration) -> Self {
		let (tx, rx) = unbounded();
		let map = MapHandle::try_clone(map).unwrap();

		let tx_clone = tx.clone();
		thread::spawn(move || {
			read_count_percpu_hash(map, interval, tx_clone);
		});

		Self { tx, rx }
	}

	pub fn next_batch(&mut self) -> Option<Batch> {
		Some(self.rx.recv().unwrap())
	}

	pub fn to_op(self) -> Operator {
		Operator::ReadCountFromPerCpuHash(self)
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
		lost_event_handler: fn(i32, u64),
	) -> Self {
		//let (tx, rx) = bounded(256);

		let (tx, rx) = unbounded();
		let (parser_tx, parser_rx): (Sender<Vec<u8>>, _) = unbounded();

		for i in 0..2 {
			let parser_rx = parser_rx.clone();
			let tx = tx.clone();
			let item_t = item_t.clone();
			let buffer_t = buffer_t.clone();
			let schema = schema.clone();
			let parser_tx = parser_tx.clone();

			thread::spawn(move || {
				while let Ok(bytes) = parser_rx.recv() {
					let batch = read_batch(&buffer_t, &item_t, &bytes, &schema);
					tx.send(batch).unwrap();
				}
			});
		}

		let parser_tx = parser_tx.clone();

		let perf_map = PerfBufferBuilder::new(map)
			.sample_cb(move |cpu: i32, bytes: &[u8]| {
				let bytes: Vec<u8> = bytes.into();
				parser_tx.send(bytes).unwrap();
			})
			.lost_cb(move |cpu: i32, count: u64| {
				lost_event_handler(cpu, count);
			})
			.build()
			.unwrap();

		thread::spawn(move || {
			println!("Polling");
			loop {
				perf_map.poll(Duration::from_secs(10)).unwrap();
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

	// TODO:
	// This parsing is still quite expensive, incurring a hashmap lookup
	// for each field in each event struct.
	for (field, bytes) in buffer_fields.iter() {
		if field == &"length" {
			len = u32::from_ne_bytes((*bytes).try_into().unwrap());
		}
		if field == &"buffer" {
			data = bytes;
		}
	}

	let mut batch_builder = BatchBuilder::from_schema(&schema);
	let mut offset = 0;
	for i in 0..len {
		let d = &data[offset..];
		let item_fields = item_t.as_cstruct_ref().unwrap().read_fields(d);
		for (field, bytes) in item_fields {
			batch_builder
				.get_column_mut(field)
				.unwrap()
				.push_bytes(bytes);
			offset += bytes.len();
		}
	}
	batch_builder.len = len as usize;

	batch_builder.build()
}

pub struct PerfEventItem {
	pub cpu: i32,
	pub batch: Batch,
}
