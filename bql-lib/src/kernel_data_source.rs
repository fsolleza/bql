
pub enum KernelDataSource {
	RawSysEnter(RawSysEnterFields),
	TaskStruct(TaskStructFields),
}

pub enum RawSysEnterFields {
	SyscallNumber
}

pub enum TaskStructFields {
	Pid
}


