use std::io;

use tokio::{select, sync::mpsc};
use yazi_fs::engine::{Attrs, Engine, Transit};
use yazi_sftp::fs::Flags;
use yazi_shared::url::{AsUrl, UrlBuf};

use super::Sftp;

// Copy in 32 MiB chunks to report progress and keep each request within its timeout
const PER_CHUNK: u64 = 32 * 1024 * 1024;

pub(super) struct ServerCopier {
	from:  UrlBuf,
	to:    UrlBuf,
	attrs: Attrs,

	prog_tx: mpsc::Sender<io::Result<u64>>,
}

impl ServerCopier {
	pub(super) fn spawn(from: UrlBuf, to: UrlBuf, attrs: Attrs) -> Transit {
		let (prog_tx, prog_rx) = mpsc::channel(20);
		let copier = Self { from, to, attrs, prog_tx };

		let handle = tokio::spawn(copier.watch());

		Transit::new(prog_rx, handle)
	}

	async fn watch(self) {
		let result = select! {
			biased;
			_ = self.prog_tx.closed() => return,
			result = self.work() => result,
		};

		if let Err(e) = result {
			self.prog_tx.send(Err(e)).await.ok();
		}
	}

	async fn work(&self) -> io::Result<()> {
		let (from, to) = (Sftp::new(self.from.as_url()).await?, Sftp::new(self.to.as_url()).await?);
		let op = from.op().await?;

		// Both handles must come from the same session for the server to resolve them
		let src = op.open(from.path, Flags::READ, &Default::default()).await?;
		let Some(len) = src.fstat().await?.size.filter(|&n| n > 0) else {
			return Err(io::ErrorKind::CrossesDevices.into());
		};

		let flags = Flags::WRITE | Flags::CREATE | Flags::TRUNCATE;
		let dist = op.open(to.path, flags, &Default::default()).await?;

		let mut offset = 0;
		while offset < len {
			let n = PER_CHUNK.min(len - offset);
			match src.copy_data(offset, n, &dist, offset).await.map_err(io::Error::from) {
				Ok(()) => {}
				Err(e) if offset == 0 && Self::fallback(&e) => {
					return Err(io::ErrorKind::CrossesDevices.into());
				}
				Err(e) => return Err(e),
			}

			offset += n;
			self.prog_tx.send(Ok(n)).await.ok();
		}

		if let Ok(attrs) = super::Attrs(self.attrs).try_into() {
			dist.fsetstat(&attrs).await.ok();
		}

		Ok(())
	}

	// Servers may advertise the extension yet refuse it for particular files or filesystems
	fn fallback(e: &io::Error) -> bool {
		use io::ErrorKind as K;

		matches!(e.kind(), K::Unsupported | K::PermissionDenied | K::Other)
	}
}
