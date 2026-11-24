use std::{io, sync::Arc, time::{Duration, SystemTime}};

use chrono::DateTime;
use deadpool::managed::Pool;
use foldhash::fast::FixedState;
use hashbrown::HashMap;
use parking_lot::Mutex;
use russh::{client::Handle, keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate, agent::AgentIdentity}};
use yazi_config::vfs::ServiceSftp;
use yazi_fs::engine::local::Local;
use yazi_shared::auth::AuthArc;

use super::{Client, Ssh};

pub(super) static CONN: Mutex<HashMap<AuthArc, Pool<Conn>, FixedState>> =
	Mutex::new(HashMap::with_hasher(FixedState::with_seed(0)));

#[derive(Clone)]
pub(super) struct Conn {
	pub(super) config: Arc<ServiceSftp>,
}

macro_rules! cfg_err {
	($($args:tt)*) => {
		russh::Error::InvalidConfig(format!($($args)*))
	};
}

impl russh::client::Handler for Conn {
	type Error = russh::Error;

	async fn check_server_key(
		&mut self,
		_server_public_key: &PublicKeyOrCertificate,
	) -> Result<bool, Self::Error> {
		Ok(true)
	}
}

impl deadpool::managed::Manager for Conn {
	type Error = io::Error;
	type Type = Client;

	async fn create(&self) -> Result<Self::Type, Self::Error> {
		let ssh = Ssh::make(&self.config).await?;
		let op = ssh.sftp().await?;
		Ok(Client { op, ssh })
	}

	async fn recycle(
		&self,
		obj: &mut Self::Type,
		_metrics: &deadpool::managed::Metrics,
	) -> deadpool::managed::RecycleResult<Self::Error> {
		if obj.is_closed() || obj.ssh.is_closed() {
			Err(deadpool::managed::RecycleError::Message("Channel closed".into()))
		} else {
			Ok(())
		}
	}
}

impl Conn {
	pub(super) fn pool(config: Arc<ServiceSftp>) -> deadpool::managed::Pool<Self> {
		let mut pools = super::CONN.lock();
		if let Some(pool) = pools.get(&config.auth)
			&& pool.manager().config == config
		{
			return pool.clone();
		}

		let auth = config.auth.clone();
		// Building only fails when a timeout is set without a runtime, and both are set here
		let pool = deadpool::managed::Pool::builder(Self { config })
			.runtime(deadpool::Runtime::Tokio1)
			// Objects are channels on one shared session, so stay under sshd's default `MaxSessions` of 10
			.max_size(8)
			.create_timeout(Some(Duration::from_secs(45)))
			.build()
			.unwrap();
		pools.insert(auth, pool.clone());
		pool
	}

	pub(super) async fn connect(
		&self,
		jump: Option<&Handle<Self>>,
	) -> Result<Handle<Self>, russh::Error> {
		let pref = Arc::new(russh::client::Config {
			inactivity_timeout: Some(std::time::Duration::from_secs(60)),
			keepalive_interval: Some(std::time::Duration::from_secs(10)),
			..Default::default()
		});

		if self.config.password.is_some() {
			self.connect_by_password(pref, jump).await
		} else if !self.config.key_file.as_os_str().is_empty()
			&& !self.config.cert_file.as_os_str().is_empty()
		{
			self.connect_by_key_and_cert(pref, jump).await
		} else if !self.config.key_file.as_os_str().is_empty() {
			self.connect_by_key(pref, jump).await
		} else if !self.config.identity_agent.as_os_str().is_empty() {
			self.connect_by_agent(pref, jump).await
		} else {
			self.connect_by_none(pref, jump).await
		}
	}

	async fn session(
		&self,
		pref: Arc<russh::client::Config>,
		jump: Option<&Handle<Self>>,
	) -> Result<Handle<Self>, russh::Error> {
		let (host, port) = (self.config.host.as_str(), self.config.port);
		let Some(jump) = jump else {
			return russh::client::connect(pref, (host, port), self.clone()).await;
		};

		let tunnel = jump.channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0).await?;
		russh::client::connect_stream(pref, tunnel.into_stream(), self.clone()).await
	}

	async fn connect_by_password(
		&self,
		pref: Arc<russh::client::Config>,
		jump: Option<&Handle<Self>>,
	) -> Result<Handle<Self>, russh::Error> {
		let Some(password) = &self.config.password else {
			return Err(cfg_err!("Password not provided"));
		};

		let mut session = self.session(pref, jump).await?;
		if session.authenticate_password(&self.config.user, password).await?.success() {
			Ok(session)
		} else {
			Err(cfg_err!("Password authentication failed"))
		}
	}

	async fn connect_by_key(
		&self,
		pref: Arc<russh::client::Config>,
		jump: Option<&Handle<Self>>,
	) -> Result<Handle<Self>, russh::Error> {
		let key_file = &self.config.key_file;
		if key_file.as_os_str().is_empty() {
			return Err(cfg_err!("Key file not provided"));
		};

		let key = Local::regular(key_file)
			.read_to_string()
			.await
			.map_err(|e| cfg_err!("Failed to read key file: {e}"))?;
		let key = russh::keys::decode_secret_key(&key, self.config.key_passphrase.as_deref())?;

		let mut session = self.session(pref, jump).await?;
		let result = session
			.authenticate_publickey(
				&self.config.user,
				PrivateKeyWithHashAlg::new(
					Arc::new(key),
					session.best_supported_rsa_hash().await?.flatten(),
				),
			)
			.await?;

		if result.success() { Ok(session) } else { Err(cfg_err!("Public key authentication failed")) }
	}

	async fn connect_by_key_and_cert(
		&self,
		pref: Arc<russh::client::Config>,
		jump: Option<&Handle<Self>>,
	) -> Result<Handle<Self>, russh::Error> {
		let key_file = &self.config.key_file;
		if key_file.as_os_str().is_empty() {
			return Err(cfg_err!("Key file not provided"));
		};

		let cert_file = &self.config.cert_file;
		if cert_file.as_os_str().is_empty() {
			return Err(cfg_err!("Cert file not provided"));
		};

		// Decode the key and cert files
		let key = Local::regular(key_file)
			.read_to_string()
			.await
			.map_err(|e| cfg_err!("Failed to read key file: {e}"))?;
		let key = russh::keys::decode_secret_key(&key, self.config.key_passphrase.as_deref())?;

		let cert = Local::regular(cert_file)
			.read_to_string()
			.await
			.map_err(|e| cfg_err!("Failed to read cert file: {e}"))?;
		let cert = russh::keys::Certificate::from_openssh(&cert)?;

		// Verify the certificate
		if !self.config.no_cert_verify {
			cert
				.verify_signature()
				.map_err(|e| cfg_err!("Certificate signature verification failed: {e}"))?;

			let now: DateTime<chrono::Local> = SystemTime::now().into();
			let start: Option<DateTime<chrono::Local>> = cert.valid_after_time().map(Into::into);
			let end: Option<DateTime<chrono::Local>> = cert.valid_before_time().map(Into::into);
			if start.is_some_and(|d| now < d) || end.is_some_and(|d| now > d) {
				return Err(cfg_err!(
					"Certificate is out of the validity range of '{}' to '{}'",
					start.map(|d| d.to_rfc2822()).as_deref().unwrap_or("unknown"),
					end.map(|d| d.to_rfc2822()).as_deref().unwrap_or("unknown")
				));
			}
		}

		let mut session = self.session(pref, jump).await?;
		if session.authenticate_openssh_cert(&self.config.user, Arc::new(key), cert).await?.success() {
			Ok(session)
		} else {
			Err(cfg_err!("Public key with certificate authentication failed"))
		}
	}

	async fn connect_by_agent(
		&self,
		pref: Arc<russh::client::Config>,
		jump: Option<&Handle<Self>>,
	) -> Result<Handle<Self>, russh::Error> {
		let identity_agent = &self.config.identity_agent;
		if identity_agent.as_os_str().is_empty() {
			return Err(cfg_err!("Identity agent not provided"));
		};

		#[cfg(unix)]
		let mut agent = russh::keys::agent::client::AgentClient::connect_uds(identity_agent).await?;
		#[cfg(windows)]
		let mut agent =
			russh::keys::agent::client::AgentClient::connect_named_pipe(identity_agent).await?;

		let identities = agent.request_identities().await?;
		let identity_count = identities.len();
		let mut session = self.session(pref, jump).await?;

		let hash_alg = session.best_supported_rsa_hash().await?.flatten();
		for identity in identities {
			let result = match identity {
				AgentIdentity::PublicKey { key, .. } => {
					session.authenticate_publickey_with(&self.config.user, key, hash_alg, &mut agent).await
				}
				AgentIdentity::Certificate { certificate, .. } => {
					session
						.authenticate_certificate_with(&self.config.user, certificate, hash_alg, &mut agent)
						.await
				}
			};
			match result {
				Ok(result) if result.success() => return Ok(session),
				Ok(result) => yazi_macro::debug!("Identity agent authentication failed: {result:?}"),
				Err(e) => yazi_macro::error!("Identity agent authentication error: {e}"),
			}
		}

		if session.authenticate_none(&self.config.user).await?.success() {
			Ok(session)
		} else if identity_count == 0 {
			Err(cfg_err!("No keys found in SSH agent"))
		} else {
			Err(cfg_err!("Identity agent authentication failed"))
		}
	}

	async fn connect_by_none(
		&self,
		pref: Arc<russh::client::Config>,
		jump: Option<&Handle<Self>>,
	) -> Result<Handle<Self>, russh::Error> {
		let mut session = self.session(pref, jump).await?;
		if session.authenticate_none(&self.config.user).await?.success() {
			Ok(session)
		} else {
			Err(cfg_err!("None authentication failed"))
		}
	}
}
