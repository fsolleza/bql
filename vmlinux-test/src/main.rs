use std::path::*;
use std::process::Command;

fn generate_vmlinux() {
    let mut cmd = Command::new("bpftool");
    cmd.arg("btf")
        .arg("dump")
        .arg("file")
        .arg("/sys/kernel/btf/vmlinux")
        .arg("format")
        .arg("c");
    let output = cmd.output().unwrap();
	println!("{:?}", std::str::from_utf8(&output.stdout).unwrap());
}

fn main() {
	generate_vmlinux();
}
