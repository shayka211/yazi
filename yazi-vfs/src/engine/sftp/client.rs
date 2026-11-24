use std::{ops::Deref, sync::Arc};

use super::Ssh;

pub struct Client {
	pub(super) op:  yazi_sftp::Operator,
	pub(super) ssh: Arc<Ssh>,
}

impl Deref for Client {
	type Target = yazi_sftp::Operator;

	fn deref(&self) -> &Self::Target { &self.op }
}
