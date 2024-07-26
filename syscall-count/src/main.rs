use clap::*;
use std::{
	thread,
	time::Duration,
	sync::atomic::{AtomicUsize, Ordering::SeqCst }
};
use libbpf_rs::{
	PerfBufferBuilder,
	skel::{SkelBuilder, OpenSkel, Skel},
};

mod syscall_count {
	include!(concat!(env!("OUT_DIR"), "/syscall_count.skel.rs"));
}
use syscall_count::*;

type Event = syscall_count_types::event_t;
type Buffer = syscall_count_types::buffer_t;

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

fn lost_event_handler(cpu: i32, count: u64) {
	eprintln!("Lost {count} events on CPU {cpu}");
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
	#[arg(short, long, default_value_t=0)]
	pid: u32,

	#[arg(short, long, default_value_t=0)]
	syscall_number: u32,
}

fn main() {
	bump_memlock_rlimit();

	let args = Args::parse();

	let skel_builder = SyscallCountSkelBuilder::default();
	let mut open_skel: OpenSyscallCountSkel = skel_builder.open().unwrap();

	open_skel.rodata_mut().TARGET_PID = args.pid;
	open_skel.rodata_mut().TARGET_SYSCALL_NUMBER = args.syscall_number;

	let mut skel = open_skel.load().unwrap();

	let perf = PerfBufferBuilder::new(skel.maps_mut().perf_ring())
		.sample_cb(move |_cpu: i32, bytes: &[u8]| {
			let ptr = bytes.as_ptr() as *const Buffer;
			let event_buffer = unsafe { *ptr };
			COUNT.fetch_add(event_buffer.length as usize, SeqCst);
		})
		.lost_cb(move |cpu: i32, count: u64| {
			eprintln!("Lost {count} events on CPU {cpu}");
		})
		.build().unwrap();

	thread::spawn(move || {
		loop {
			perf.poll(Duration::from_secs(10)).unwrap();
		}
	});

	skel.attach().unwrap();
	thread::spawn(counter).join().unwrap();
}
