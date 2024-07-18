use std::process::Command;
use libbpf_rs::{PerfBufferBuilder, OpenObject, ObjectBuilder};
use std::{
	time::Duration,
	sync::atomic::{
		AtomicUsize,
		Ordering::SeqCst
	},
	thread,
};

static COUNT: AtomicUsize = AtomicUsize::new(0);

fn counter() {
	loop {
		println!("Count: {}", COUNT.swap(0, SeqCst));
		thread::sleep(Duration::from_secs(1));
	}
}


pub fn bump_memlock_rlimit() {
	let rlimit = libc::rlimit {
		rlim_cur: 128 << 20,
		rlim_max: 128 << 20,
	};

	if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
		panic!("Failed to increase rlimit");
	}
}


fn compile_program(src_path: &str, vmlinux_dir: &str, dst_path: &str) {

	let mut cmd = Command::new("clang");

	// Code yoinked from libbpf-cargo's compilation flags
	cmd.arg(format!("-I{}", vmlinux_dir))
		.arg("-D__TARGET_ARCH_x86_64")
		// Explicitly disable stack protector logic, which doesn't work with
		// BPF. See https://lkml.org/lkml/2020/2/21/1000.
		.arg("-fno-stack-protector")
		.arg("-g")
		.arg("-O2")
		.arg("-target")
		.arg("bpf")
		.arg("-c")
		.arg(src_path)
		.arg("-o")
		.arg(dst_path);

	let output = cmd.output().expect("Failed to execute clang");
	if !output.status.success() {
		let err = String::from_utf8_lossy(&output.stderr).to_string();
		panic!("Compile failed: {err}");
	}
}

fn parse_program(obj_path: &str) -> OpenObject {
	ObjectBuilder::default().open_file(obj_path).unwrap()
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub tid: u32,
    pub syscall_number: u64,
    pub start_time: u64,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct Buffer {
    pub length: u32,
    pub buffer: [Event; 256],
}

impl Default for Buffer {
	fn default() -> Self {
		Buffer {
			length: 0,
			buffer: [Event::default(); 256],
		}
	}
}

fn read_into_buffer(bytes: &[u8]) -> Buffer {
	let mut buffer = Buffer::default();

	let mut offset = 0;
	println!("{:?}", &bytes[0..4]);
	let len = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
	buffer.length = len;

	offset += 8; // account for padding;
	println!("Length: {}", len);
	for i in 0..len {
		let pid = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
		offset += 4;

		let tid = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
		offset += 4;

		let syscall_number = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
		offset += 8;

		let start_time = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
		offset += 8;
		buffer.buffer[i as usize] = Event { pid, tid, syscall_number, start_time };
	}

	buffer

}

fn main() {

	bump_memlock_rlimit();
	compile_program("tmp/syscall_count.bpf.c", "./vmlinux", "tmp/output.out");
	let open_obj = parse_program("tmp/output.out");
	let mut obj = open_obj.load().unwrap();
	let mut prog = obj.prog_mut("handle_sys_enter").unwrap();
	let link = prog.attach().unwrap();

	let perf_buffer = PerfBufferBuilder::new(obj.map("perf_ring").unwrap())
		.sample_cb(move |_cpu: i32, bytes: &[u8]| {
			println!("Got batch with length {}", bytes.len());
			let read_buffer = read_into_buffer(bytes);
			let ptr = bytes.as_ptr() as *const Buffer;
			let event_buffer = unsafe { *ptr };
			assert_eq!(read_buffer, event_buffer);
			COUNT.fetch_add(event_buffer.length as usize, SeqCst);
		})
		.lost_cb(move |cpu: i32, count: u64| {
			eprintln!("Lost {count} events on CPU {cpu}");
		})
		.build().unwrap();

	thread::spawn(move || {
		loop {
			perf_buffer.poll(Duration::from_secs(10)).unwrap();
		}
	});

	thread::spawn(counter).join().unwrap();
}
