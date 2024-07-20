use libbpf_rs::{
	PerfBufferBuilder,
	PerfBuffer,
	OpenObject,
	ObjectBuilder,
	Object,
	Link,
	Map
};
use crossbeam::channel::*;
use std::{
	collections::HashMap,
	process::Command,
	time::Duration,
	ops::Deref,
	thread,
	env::temp_dir,
	fs::{create_dir_all, OpenOptions, File},
	io::prelude::*,
	path::{PathBuf, Path},
	env,
};

pub fn bump_memlock_rlimit() {
	let rlimit = libc::rlimit {
		rlim_cur: 128 << 20,
		rlim_max: 128 << 20,
	};

	if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
		panic!("Failed to increase rlimit");
	}
}

fn build_path() -> PathBuf {
	let mut a: PathBuf = "tmp-bql-lib-build".into();
	create_dir_all(&a).unwrap();
	a
}

pub struct BpfCode {
	code: String,
}

impl BpfCode {
	pub fn new(code: &str) -> Self {
		Self {
			code: code.into()
		}
	}

	pub fn compile_and_load(&self) -> BpfObject {

		let source_code_path = {
			let mut a = build_path();
			a.push("bpf_source_code.bpf.c");
			a
		};

		let object_path = {
			let mut a = build_path();
			a.push("bpf_object");
			a
		};

		{
			let mut source_code_file =
				OpenOptions::new()
				.write(true)
				.truncate(true)
				.create(true)
				.open(&source_code_path)
				.unwrap();
			write!(source_code_file, "{}", &self.code);
		}

		let obj = generate_bpf_object(&source_code_path, &object_path);

		BpfObject::new(obj)
	}
}

fn generate_vmlinux<S: AsRef<Path>>(vmlinux_dir: S) {
	let mut cmd = Command::new("bpftool");
	cmd.arg("btf")
		.arg("dump")
		.arg("file")
		.arg("/sys/kernel/btf/vmlinux")
		.arg("format")
		.arg("c");
	let output = cmd.output().unwrap();

	{
		let mut vmlinux_file = 
			OpenOptions::new()
			.write(true)
			.truncate(true)
			.create(true)
			.open(vmlinux_dir.as_ref().join("vmlinux.h"))
			.unwrap();
		vmlinux_file.write_all(output.stdout.as_slice()).unwrap();
	}
}

fn generate_bpf_object<S, D>(src_path: S, dst_path: D) -> Object
where
	S: AsRef<Path>,
	D: AsRef<Path>,
{

	generate_vmlinux(src_path.as_ref().parent().unwrap());

	let mut cmd = Command::new("clang");
	// Code yoinked from libbpf-cargo's compilation flags
	//cmd.arg(format!("-I{:?}", vmlinux_dir.as_ref()))
	cmd.arg("-D__TARGET_ARCH_x86_64")
		// Explicitly disable stack protector logic, which doesn't work with
		// BPF. See https://lkml.org/lkml/2020/2/21/1000.
		.arg("-fno-stack-protector")
		.arg("-g")
		.arg("-O2")
		.arg("-target")
		.arg("bpf")
		.arg("-c")
		.arg(src_path.as_ref())
		.arg("-o")
		.arg(dst_path.as_ref());

	let output = cmd.output().expect("Failed to execute clang");
	if !output.status.success() {
		let err = String::from_utf8_lossy(&output.stderr).to_string();
		panic!("Compile failed: {err}");
	}
	let open_obj = ObjectBuilder::default().open_file(dst_path).unwrap();
	let obj = open_obj.load().unwrap();

	obj
}

pub struct BpfObject {
	object: Object,
	program_links: HashMap<String, Link>,
	maps: HashMap<String, BpfMap>,
}

impl BpfObject {
	fn new(object: Object) -> Self {
		Self {
			object,
			program_links: HashMap::new(),
			maps: HashMap::new(),
		}
	}

	pub fn attach_programs(&mut self) {
		for prog in self.object.progs_iter_mut() {
			let name = String::from(prog.name());
			let link = prog.attach().unwrap();
			self.program_links.insert(name, link);
		}
	}
}

pub enum BpfMap {
	PerfEventArray(PerfEventArray),
}

pub struct PerfEventItem {
	pub cpu: i32,
	pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct PerfEventArray {
	receiver: Receiver<PerfEventItem>
}

impl PerfEventArray {
	fn init(map: &Map) -> Self {
		let (tx, rx) = unbounded();
		let perf_buffer = PerfBufferBuilder::new(map)
			.sample_cb(move |cpu: i32, bytes: &[u8]| {
				let item = PerfEventItem { cpu, data: bytes.into() };
				tx.send(item).unwrap();
			})
			.lost_cb(move |cpu: i32, count: u64| {
				eprintln!("Lost {count} events on CPU {cpu}");
			})
			.build()
			.unwrap();
		thread::spawn(move || {
			loop {
				perf_buffer.poll(Duration::from_secs(1)).unwrap();
			}
		});
		Self { receiver: rx }
	}
}

impl Deref for PerfEventArray {
	type Target = Receiver<PerfEventItem>;
	fn deref(&self) -> &Self::Target {
		&self.receiver
	}
}
