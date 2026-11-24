yazi_macro::mod_flat!(client conn demand read_dir rw_file server_copier sftp ssh stat);

pub(super) fn init() {
	tokio::spawn(async {
		loop {
			tokio::time::sleep(std::time::Duration::from_secs(60)).await;

			CONN.lock().retain(|_, pool| {
				pool.retain(|_, metrics| metrics.last_used().as_secs() < 300);

				let status = pool.status();
				status.size > 0 || status.waiting > 0
			});

			SESSIONS
				.lock()
				.retain(|_, slot| slot.try_lock().map_or(true, |weak| weak.strong_count() > 0));
		}
	});
}
