// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
mod syscall;
use core::time::Duration;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::{bounded, Receiver, Sender};
use lazy_static::*;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::PerfBufferBuilder;
use std::process;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering::SeqCst};
use std::thread;
use syscall::SyscallEventBuffer;

mod syscall_filter {
	include!(concat!(env!("OUT_DIR"), "/syscall_filter.skel.rs"));
}
use syscall_filter::*;

lazy_static! {
	static ref EVENT_CHAN: (Sender<SyscallEventBuffer>, Receiver<SyscallEventBuffer>) =
		bounded(1024);
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);
static DROPPED: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicBool = AtomicBool::new(false);

fn counter() {
	let mut sec = 0;
	while !(DONE.load(SeqCst)) {
		let count = COUNTER.swap(0, SeqCst);
		let dropped = DROPPED.swap(0, SeqCst);
		println!("{} Retrieved: {}, Dropped: {}", sec, count, dropped);
		std::thread::sleep(std::time::Duration::from_secs(1));
		sec += 1;
	}
	thread::sleep(std::time::Duration::from_secs(2));
}

pub fn bump_memlock_rlimit() -> Result<()> {
	let rlimit = libc::rlimit {
		rlim_cur: 128 << 20,
		rlim_max: 128 << 20,
	};

	if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
		bail!("Failed to increase rlimit");
	}

	Ok(())
}

fn event_receiver() {
	let rx = EVENT_CHAN.1.clone();
	let mut v = Vec::new();
	while let Ok(buff) = rx.recv() {
		for i in 0usize..buff.len as usize {
			v.push(buff.buffer[i]);
			if v.len() == 1024 {
				COUNTER.fetch_add(1024, SeqCst);
				v.clear();
			}
		}
	}
}

fn event_handler(_cpu: i32, bytes: &[u8]) {
	let tx = EVENT_CHAN.0.clone();
	let bytes_ptr = bytes.as_ptr();
	let ptr = bytes_ptr as *const SyscallEventBuffer;
	let event_buffer = unsafe { *ptr };
	tx.send(event_buffer).unwrap();
}

fn lost_event_handler(cpu: i32, count: u64) {
	eprintln!("Lost {count} events on CPU {cpu}");
}

fn attach_and_run(target_pid: u32) -> Result<()> {
	println!("Attaching");
	let skel_builder = SyscallFilterSkelBuilder::default();
	let mut open_skel = skel_builder.open()?;
	open_skel.rodata().my_pid = process::id();
	open_skel.rodata().target_pid = target_pid;
	let mut skel = open_skel.load()?;
	skel.attach()?;
	let perf = PerfBufferBuilder::new(skel.maps_mut().perf_buffer())
		// On sample, pass to event handler
		.sample_cb(event_handler)
		// On lost sample, pass to lost event handler
		.lost_cb(lost_event_handler)
		.build()?;
	loop {
		perf.poll(Duration::from_secs(10))?;
	}
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
	#[arg(short, long)]
	pid: u32,
}

fn main() {
	bump_memlock_rlimit().unwrap();
	let args = Args::parse();
	let _txrx = EVENT_CHAN.clone();
	thread::spawn(counter);
	thread::spawn(event_receiver);
	let pid = args.pid;
	thread::spawn(move || {
		attach_and_run(pid).unwrap();
	});
	loop {
		thread::sleep(Duration::from_secs(10));
	}
}
