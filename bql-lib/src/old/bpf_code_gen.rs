pub struct PerfEventArray {
	id: u64,
}

impl PerfEventArray {
	pub fn new() -> Self {
		let id = thread_rng().gen();
		Self { id }
	}

	pub fn id(&self) -> u64 {
		self.id
	}

	pub fn generate(&self) -> String {
		perf_event_array_generate(self.id)
	}
}

fn perf_event_array_generate(id: u64) -> String {
		format!(
"
struct {{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
}} perf_event_array_{} SEC(\".maps\");
"
	, id)
}

