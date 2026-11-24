use std::{io, process::Output, sync::{Arc, Weak}};

use foldhash::fast::FixedState;
use hashbrown::HashMap;
use parking_lot::Mutex;
use russh::ChannelMsg;
use yazi_config::{VFS, vfs::ServiceSftp};
use yazi_shared::auth::{Auth, AuthArc, AuthKind, Scheme};

use super::Conn;

type Slot = Arc<tokio::sync::Mutex<Weak<Ssh>>>;

pub(super) static SESSIONS: Mutex<HashMap<AuthArc, Slot, FixedState>> =
	Mutex::new(HashMap::with_hasher(FixedState::with_seed(0)));

pub(super) struct Ssh {
	config: Arc<ServiceSftp>,
	handle: russh::client::Handle<Conn>,
	// Keeps the jump host alive for as long as this session tunnels through it
	_jump:  Option<Arc<Self>>,
}

impl Ssh {
	pub(super) async fn make(config: &Arc<ServiceSftp>) -> io::Result<Arc<Self>> {
		let mut jump = None;
		for hop in Self::hops(config)? {
			jump = Some(Self::shared(hop, jump).await?);
		}

		Self::shared(config.clone(), jump).await
	}

	pub(super) async fn sftp(&self) -> io::Result<yazi_sftp::Operator> {
		let channel = async {
			let channel = self.handle.channel_open_session().await?;
			channel.request_subsystem(true, "sftp").await?;
			Ok::<_, russh::Error>(channel)
		}
		.await
		.map_err(|e| {
			io::Error::other(format!("Failed to open SFTP channel on `{}`: {e}", self.config.domain))
		})?;

		let mut op = yazi_sftp::Operator::make(channel.into_stream());
		op.init().await?;
		Ok(op)
	}

	pub(super) async fn exec(&self, command: &[u8]) -> io::Result<Output> {
		let mut channel = self.handle.channel_open_session().await.map_err(io::Error::other)?;
		channel.exec(true, command).await.map_err(io::Error::other)?;
		channel.eof().await.map_err(io::Error::other)?;

		let (mut stdout, mut stderr, mut code) = (vec![], vec![], None);
		while let Some(msg) = channel.wait().await {
			match msg {
				ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
				ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
				ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
				_ => {}
			}
		}

		// Servers omit the exit status when the command is killed by a signal
		Ok(Output { status: exit_status(code.unwrap_or(255)), stdout, stderr })
	}

	pub(super) fn is_closed(&self) -> bool { self.handle.is_closed() }

	// Sessions are shared, so all channels to a server, and all tunnels through it, reuse one connection
	async fn shared(config: Arc<ServiceSftp>, jump: Option<Arc<Self>>) -> io::Result<Arc<Self>> {
		let slot = SESSIONS.lock().entry(config.auth.clone()).or_default().clone();
		let mut weak = slot.lock().await;

		if let Some(ssh) = weak.upgrade()
			&& ssh.config == config
			&& !ssh.is_closed()
		{
			return Ok(ssh);
		}

		let conn = Conn { config };
		let handle = conn.connect(jump.as_deref().map(|s| &s.handle)).await.map_err(|e| {
			io::Error::other(format!("Failed to connect to SFTP server `{}`: {e}", conn.config.domain))
		})?;

		let ssh = Arc::new(Self { config: conn.config, handle, _jump: jump });
		*weak = Arc::downgrade(&ssh);
		Ok(ssh)
	}

	// Jump hosts of the given server, ordered from the first hop to the last
	fn hops(config: &ServiceSftp) -> io::Result<Vec<Arc<ServiceSftp>>> {
		let mut hops: Vec<Arc<ServiceSftp>> = vec![];
		let mut next = config.proxy_jump.clone();

		while let Some(domain) = next {
			let hop: Arc<ServiceSftp> = VFS.service(&Auth::new(AuthKind::Sftp, Scheme::Sftp, domain))?;
			if hop.auth == config.auth || hops.iter().any(|h| h.auth == hop.auth) {
				return Err(io::Error::other(format!(
					"Cyclic proxy jump through SFTP server `{}`",
					hop.domain
				)));
			}

			next = hop.proxy_jump.clone();
			hops.push(hop);
		}

		hops.reverse();
		Ok(hops)
	}
}

#[cfg(unix)]
fn exit_status(code: u32) -> std::process::ExitStatus {
	std::os::unix::process::ExitStatusExt::from_raw(((code & 0xff) << 8) as i32)
}

#[cfg(windows)]
fn exit_status(code: u32) -> std::process::ExitStatus {
	std::os::windows::process::ExitStatusExt::from_raw(code)
}
