use std::{
	process::Command,
	collections::HashMap,
};
use libbpf_rs::{
	PerfBufferBuilder,
	OpenObject,
	ObjectBuilder,
	Object,
	Link,
	Program,
	Map
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

pub fn compile_and_open(
	src_path: &str,
	vmlinux_dir: &str,
	obj_path: &str
) -> OpenObject {
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
		.arg(obj_path);

	let output = cmd.output().expect("Failed to execute clang");
	if !output.status.success() {
		let err = String::from_utf8_lossy(&output.stderr).to_string();
		panic!("Compile failed: {err}");
	}
	ObjectBuilder::default().open_file(obj_path).unwrap()
}
