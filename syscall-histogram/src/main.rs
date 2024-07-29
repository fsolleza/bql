// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
mod syscall;

use anyhow::bail;
use anyhow::Result;
use chrono::prelude::*;
use clap::Parser;
use crossbeam::channel::{bounded, Receiver, Sender};
use lazy_static::*;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapFlags;
use libbpf_rs::PerfBufferBuilder;
use std::collections::HashMap;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::thread;
use std::time::{self, Duration};
use syscall::SyscallEventBuffer;

mod syscall_filter {
	include!(concat!(env!("OUT_DIR"), "/syscall_histogram.skel.rs"));
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

fn attach_and_run(target_pid: u32) -> Result<()> {
	println!("Attaching");
	let skel_builder = SyscallHistogramSkelBuilder::default();
	let mut open_skel = skel_builder.open()?;
	open_skel.rodata().my_pid = process::id();
	open_skel.rodata().target_pid = target_pid;
	let mut skel = open_skel.load()?;
	skel.attach()?;
	let mut value: usize = 0;
	let mut last_count = HashMap::new();
	loop {
		thread::sleep(Duration::from_secs(1));
		let mut maps_mut = skel.maps_mut();
		let map: _ = maps_mut.syscall_map();
		let utc: DateTime<Utc> = Utc::now();
		let mut v = Vec::new();
		for k in map.keys() {
			let read_values: Vec<Vec<u8>> =
				map.lookup_percpu(&k, MapFlags::ANY).unwrap().unwrap();
			let mut value = 0;
			for read_value in read_values {
				value += i32::from_ne_bytes(read_value.try_into().unwrap());
			}
			let key = i32::from_ne_bytes(k.try_into().unwrap());
			let last_value = last_count.entry(key).or_insert(0);
			if value > *last_value {
				v.push((utc, key, value - *last_value));
				*last_value = value;
			}
		}

		for i in v {
			println!("{:?}", i);
		}
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
	//let args = Args::parse();
	let _txrx = EVENT_CHAN.clone();
	thread::spawn(counter);
	thread::spawn(move || {
		attach_and_run(0).unwrap();
	});
	loop {
		thread::sleep(Duration::from_secs(10));
	}
}
