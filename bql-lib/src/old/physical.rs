use std::sync::Arc;

pub struct KernelFilter { }

pub struct UserFilter { }

pub enum UserPhysicalOperator {
	UserFilter(UserFilter),
}

pub enum KernelPhysicalOperator {
	KernelFilter(KernelFilter),
}

pub struct KernelPhysicalPlan {
	operator: KernelPhysicalOperator,
	next: Arc<KernelPhysicalPlan>,
}
