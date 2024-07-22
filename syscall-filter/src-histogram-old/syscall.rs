use serde::*;

#[repr(C)]
#[derive(
	Serialize, Deserialize, Eq, PartialEq, Copy, Clone, Debug, Default,
)]
pub struct SyscallEvent {
	pub pid: u32,
	pub tid: u32,
	pub syscall_number: u64,
	pub start_time: u64,
	pub duration: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SyscallEventBuffer {
	pub len: u32,
	pub buffer: [SyscallEvent; 256],
}

impl Default for SyscallEventBuffer {
	fn default() -> Self {
		Self {
			len: 0,
			buffer: [SyscallEvent::default(); 256],
		}
	}
}
