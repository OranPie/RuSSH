//! Integration harness and smoke scenarios for RuSSH.
//!
//! This crate wires together all RuSSH subsystems to verify end-to-end
//! behaviour and provide interoperability helpers.
//!
//! ## Smoke scenarios
//!
//! [`run_handshake_smoke`] exercises the full connection lifecycle:
//! config parse → transport negotiation → auth → channel open → teardown.
//!
//! ## OpenSSH interop helpers
//!
//! - [`openssh_available`] — returns `true` if the `ssh` binary is on `PATH`.
//! - [`openssh_version`] — returns the OpenSSH version string.
//! - [`run_openssh_version_check`] — verifies OpenSSH is callable, or skips
//!   gracefully when it is not installed.
//!
//! These helpers form the foundation for future interoperability test suites
//! that spawn real OpenSSH client/server processes against RuSSH endpoints.
#![cfg_attr(not(unix), allow(clippy::items_after_test_module))]

use std::future::ready;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use russh_auth::{AuthEngine, AuthRequest, ServerAuthPolicy};
use russh_channel::{Channel, ChannelKind, ConnectionPool};
use russh_config::parse_config;
use russh_core::{
    AlgorithmSet, PacketCodec, PacketFrame, PacketParser, RusshError, RusshErrorCategory,
};
use russh_crypto::Signer;
use russh_scp::{ScpClient, ScpCopyOptions};
use russh_sftp::SftpClient;
use russh_transport::{
    ClientConfig, ClientSession, KexInitProposal, SessionState, TransportMessage,
};

/// Simple integration scenario with a fixed name and action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InteropScenario {
    pub name: String,
    pub target_banner: String,
}

impl InteropScenario {
    #[must_use]
    pub fn openssh_smoke() -> Self {
        Self {
            name: "openssh-smoke".to_string(),
            target_banner: "SSH-2.0-OpenSSH_9.x".to_string(),
        }
    }
}

/// Run an end-to-end bootstrap scenario using workspace crates.
pub async fn run_bootstrap_scenario(
    scenario: &InteropScenario,
    config_text: &str,
) -> Result<(), RusshError> {
    ready(()).await;

    let parsed_config = parse_config(config_text)?;
    if parsed_config.directives.is_empty() {
        return Err(RusshError::new(
            RusshErrorCategory::Config,
            "scenario config must include at least one directive",
        ));
    }

    let mut client = ClientSession::new(ClientConfig::secure_defaults("alice"));
    client.handshake(&scenario.target_banner).await?;
    let _kexinit = client.send_kexinit()?;
    client.receive_message(TransportMessage::KexInit {
        proposal: Box::new(KexInitProposal::from_algorithms(
            [0x77; 16],
            AlgorithmSet::secure_defaults(),
        )),
    })?;
    client.receive_message(TransportMessage::NewKeys)?;

    let _service_request = client.send_service_request("ssh-userauth")?;
    client.receive_message(TransportMessage::ServiceAccept {
        service: "ssh-userauth".to_string(),
    })?;

    if client.state() != SessionState::Established {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "client session did not reach established state",
        ));
    }

    let auth_engine = AuthEngine::new(ServerAuthPolicy::secure_defaults());
    let auth = auth_engine.evaluate(&AuthRequest::Password {
        user: "alice".to_string(),
        password: "test-password".to_string(),
    });
    if !matches!(auth, russh_auth::AuthResult::Accepted) {
        return Err(RusshError::new(
            RusshErrorCategory::Auth,
            "bootstrap auth failed",
        ));
    }

    let pool = ConnectionPool::new();
    pool.insert("default", client)?;

    let _channel = Channel::open(ChannelKind::Session);
    Ok(())
}

/// Validate that a chunked packet stream can be decoded into complete frames.
pub fn decode_chunked_stream(
    codec: PacketCodec,
    chunks: &[&[u8]],
) -> Result<Vec<PacketFrame>, RusshError> {
    let mut parser = PacketParser::new(codec);
    let mut frames = Vec::new();

    for chunk in chunks {
        parser.feed(chunk);
        while let Some(frame) = parser.next_frame()? {
            frames.push(frame);
        }
    }

    if parser.buffered_len() != 0 {
        return Err(RusshError::new(
            RusshErrorCategory::Protocol,
            "stream ended with incomplete packet frame",
        ));
    }

    Ok(frames)
}

/// Simulate full encoded message flow (KEX + service accept) using packet codec.
pub fn run_encoded_transport_flow(codec: &PacketCodec) -> Result<SessionState, RusshError> {
    let mut client = ClientSession::new(ClientConfig::secure_defaults("alice"));

    let future = client.handshake("SSH-2.0-OpenSSH_9.x");
    futures_block_on(future)?;

    let _sent_kex = client.send_kexinit()?;

    let inbound_newkeys = TransportMessage::NewKeys.encode(codec)?;
    client.receive_encoded_message(codec, &inbound_newkeys)?;

    let _request = client.send_service_request("ssh-userauth")?;

    let inbound_accept = TransportMessage::ServiceAccept {
        service: "ssh-userauth".to_string(),
    }
    .encode(codec)?;
    client.receive_encoded_message(codec, &inbound_accept)?;

    Ok(client.state())
}

/// Simulate local SFTP operations for chunked transfer and metadata workflows.
pub fn run_sftp_filesystem_flow() -> Result<(), RusshError> {
    let root = unique_temp_path("russh_integration_sftp");
    let _cleanup = TempPathGuard::new(root.clone());
    std::fs::create_dir_all(&root).map_err(|error| {
        RusshError::new(
            RusshErrorCategory::Io,
            format!("failed to create temp SFTP root {:?}: {error}", root),
        )
    })?;

    let client = SftpClient::new(Channel::open(ChannelKind::Session), root);
    client.write_file("nested/hello.txt", b"hello")?;
    client.write_file_chunk("nested/hello.txt", 5, b"-world")?;
    client.write_file("nested/old_name.txt", b"x")?;

    let middle = client.read_file_chunk("nested/hello.txt", 3, 5)?;
    if middle != b"lo-wo" {
        return Err(RusshError::new(
            RusshErrorCategory::Interop,
            "SFTP chunk read returned unexpected data",
        ));
    }

    let stat = client.stat("nested/hello.txt")?;
    if !stat.is_file || stat.size != 11 {
        return Err(RusshError::new(
            RusshErrorCategory::Interop,
            "SFTP stat metadata does not match expected file shape",
        ));
    }

    let entries = client.list_dir("nested")?;
    if entries.len() < 2 {
        return Err(RusshError::new(
            RusshErrorCategory::Interop,
            "SFTP directory listing returned fewer entries than expected",
        ));
    }

    client.rename("nested/old_name.txt", "nested/new_name.txt")?;
    client.remove_file("nested/new_name.txt")?;

    Ok(())
}

/// Simulate SCP recursive copy operations and verify transfer integrity + stats.
pub fn run_scp_recursive_flow() -> Result<(), RusshError> {
    let base = unique_temp_path("russh_integration_scp");
    let _cleanup = TempPathGuard::new(base.clone());
    let source = base.join("source");
    let target = base.join("target");
    std::fs::create_dir_all(source.join("deep")).map_err(|error| {
        RusshError::new(
            RusshErrorCategory::Io,
            format!("failed to create source tree {:?}: {error}", source),
        )
    })?;
    std::fs::write(source.join("a.txt"), b"abc").map_err(|error| {
        RusshError::new(
            RusshErrorCategory::Io,
            format!("failed to write source file: {error}"),
        )
    })?;
    std::fs::write(source.join("deep").join("b.txt"), b"defg").map_err(|error| {
        RusshError::new(
            RusshErrorCategory::Io,
            format!("failed to write nested source file: {error}"),
        )
    })?;

    let client = ScpClient::new(Channel::open(ChannelKind::Session));
    let stats =
        client.recursive_copy_with_options(&source, &target, ScpCopyOptions::secure_defaults())?;
    if stats.files_copied != 2 || stats.bytes_copied != 7 {
        return Err(RusshError::new(
            RusshErrorCategory::Interop,
            "SCP transfer stats mismatch",
        ));
    }

    let copied = std::fs::read(target.join("deep").join("b.txt")).map_err(|error| {
        RusshError::new(
            RusshErrorCategory::Io,
            format!("failed to read copied file: {error}"),
        )
    })?;
    if copied != b"defg" {
        return Err(RusshError::new(
            RusshErrorCategory::Interop,
            "SCP copied file content mismatch",
        ));
    }

    Ok(())
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}_{now_nanos}"))
}

struct TempPathGuard {
    path: PathBuf,
}

impl TempPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        remove_path_if_exists(&self.path);
    }
}

fn remove_path_if_exists(path: &Path) {
    if !path.exists() {
        return;
    }

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return,
    };

    if metadata.is_dir() {
        let _ = std::fs::remove_dir_all(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(all(test, unix))]
async fn interop_test_guard() -> tokio::sync::OwnedSemaphorePermit {
    static LOCK: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1)))
        .clone()
        .acquire_owned()
        .await
        .expect("interop test semaphore closed")
}

fn futures_block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);

    loop {
        match Pin::as_mut(&mut future).poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// Checks whether the `ssh` binary is available on PATH.
pub fn openssh_available() -> bool {
    std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns the version string of the installed OpenSSH client, or None.
pub fn openssh_version() -> Option<String> {
    let output = std::process::Command::new("ssh").arg("-V").output().ok()?;
    // ssh -V prints to stderr
    let bytes = if output.stderr.is_empty() {
        output.stdout
    } else {
        output.stderr
    };
    String::from_utf8(bytes).ok().map(|s| s.trim().to_string())
}

/// Run a self-contained interop smoke test.
/// Returns `Ok(())` if OpenSSH is not available (skip gracefully).
/// Returns `Err` if OpenSSH is available but the test fails.
pub fn run_openssh_version_check() -> Result<(), String> {
    if !openssh_available() {
        return Ok(()); // skip — OpenSSH not installed
    }
    let version = openssh_version().unwrap_or_default();
    if version.is_empty() {
        return Err("OpenSSH available but version string is empty".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use russh_core::{PacketCodec, PacketFrame, RusshErrorCategory};
    use russh_transport::SessionState;

    use super::{
        InteropScenario, decode_chunked_stream, run_bootstrap_scenario, run_encoded_transport_flow,
        run_scp_recursive_flow, run_sftp_filesystem_flow,
    };

    #[test]
    fn bootstrap_scenario_succeeds() {
        let scenario = InteropScenario::openssh_smoke();
        let config = "Host example\nUser alice\n";

        let result = super::futures_block_on(run_bootstrap_scenario(&scenario, config));
        assert!(result.is_ok());
    }

    #[test]
    fn chunked_stream_decodes_frames() {
        let codec = PacketCodec::with_defaults();
        let one = codec
            .encode(&PacketFrame::new(vec![21, 1, 2]))
            .expect("encode should succeed");
        let two = codec
            .encode(&PacketFrame::new(vec![94, 9]))
            .expect("encode should succeed");

        let mut stream = Vec::new();
        stream.extend_from_slice(&one);
        stream.extend_from_slice(&two);

        let chunks: [&[u8]; 3] = [&stream[..7], &stream[7..13], &stream[13..]];
        let frames = decode_chunked_stream(codec, &chunks).expect("decode should succeed");

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].message_type(), Some(21));
        assert_eq!(frames[1].message_type(), Some(94));
    }

    #[test]
    fn chunked_stream_rejects_incomplete_frame() {
        let codec = PacketCodec::with_defaults();
        let frame = codec
            .encode(&PacketFrame::new(vec![5, 7, 9]))
            .expect("encode should succeed");
        let chunks: [&[u8]; 2] = [&frame[..6], &[]];

        let error = decode_chunked_stream(codec, &chunks)
            .expect_err("decoder must reject partial trailing frame");

        assert_eq!(error.category(), RusshErrorCategory::Protocol);
    }

    #[test]
    fn encoded_transport_flow_reaches_established_state() {
        let codec = PacketCodec::with_defaults();

        let state = run_encoded_transport_flow(&codec).expect("encoded flow should succeed");

        assert_eq!(state, SessionState::Established);
    }

    #[test]
    fn sftp_filesystem_flow_succeeds() {
        run_sftp_filesystem_flow().expect("sftp flow should succeed");
    }

    #[test]
    fn scp_recursive_flow_succeeds() {
        run_scp_recursive_flow().expect("scp flow should succeed");
    }

    #[test]
    fn openssh_version_check_or_skip() {
        super::run_openssh_version_check().expect("openssh version check failed");
    }
}

// ── OpenSSH interop test infrastructure ──────────────────────────────────────

use std::net::TcpListener as StdTcpListener;
use std::process::{Child, Command};

use russh_crypto::{Ed25519Signer, OsRng, RandomSource};

/// A running `sshd` instance with ephemeral keys in a temp directory.
///
/// Dropped automatically: the sshd process is killed when the fixture goes out
/// of scope.
pub struct SshdFixture {
    /// TCP port on which sshd is listening.
    pub port: u16,
    /// User Ed25519 key registered in `authorized_keys`.
    pub user_key_seed: [u8; 32],
    _dir: TempPathGuard,
    child: Child,
}

impl SshdFixture {
    /// Spawn a real `sshd` on a random loopback port.
    ///
    /// Returns `None` if the `sshd` binary is not found or setup fails.
    /// Tests should skip when `None` is returned.
    pub fn spawn() -> Option<Self> {
        // Verify sshd is available.
        let sshd_path = ["/usr/sbin/sshd", "/usr/bin/sshd", "sshd"]
            .iter()
            .find(|p| std::path::Path::new(p).exists() || which_on_path(p))?
            .to_string();

        let port = free_port()?;

        let dir_path = unique_temp_path("russh_sshd_fixture");
        std::fs::create_dir_all(&dir_path).ok()?;

        // Generate an Ed25519 host key using ssh-keygen (sshd needs OpenSSH format).
        let host_key_path = dir_path.join("ssh_host_ed25519_key");
        let ok = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                host_key_path.to_str()?,
                "-N",
                "",
                "-q",
            ])
            .status()
            .ok()?
            .success();
        if !ok {
            return None;
        }
        set_permissions_600(&host_key_path);

        // Generate the user key using russh-crypto (we need the signer on the client side).
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let user_signer = Ed25519Signer::from_seed(&seed);
        let public_key_blob = user_signer.public_key_blob();

        // Write authorized_keys in OpenSSH format: "ssh-ed25519 BASE64BLOB comment\n"
        let auth_keys_path = dir_path.join("authorized_keys");
        let auth_key_line = format!(
            "ssh-ed25519 {} russh-test\n",
            base64_standard(&public_key_blob)
        );
        std::fs::write(&auth_keys_path, auth_key_line).ok()?;
        set_permissions_600(&auth_keys_path);

        // Write a minimal sshd_config.
        let config_path = dir_path.join("sshd_config");
        let config_text = format!(
            "Port {port}\n\
             HostKey {host_key}\n\
             AuthorizedKeysFile {auth_keys}\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             ChallengeResponseAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             StrictModes no\n\
             PermitRootLogin yes\n\
             AllowUsers {user}\n\
             LogLevel ERROR\n\
             Subsystem sftp internal-sftp\n",
            host_key = host_key_path.display(),
            auth_keys = auth_keys_path.display(),
            user = std::env::var("USER").unwrap_or_else(|_| "root".into()),
        );
        std::fs::write(&config_path, config_text).ok()?;

        // Spawn sshd in foreground mode.
        let mut child = Command::new(&sshd_path)
            .args(["-D", "-f", config_path.to_str()?])
            .spawn()
            .ok()?;

        // Wait up to 3 s for the port to accept connections.
        let ready = wait_for_tcp_ready(port, Some(&mut child), std::time::Duration::from_secs(3));
        if !ready {
            return None;
        }

        Some(SshdFixture {
            port,
            user_key_seed: seed,
            _dir: TempPathGuard::new(dir_path),
            child,
        })
    }

    /// Spawn sshd using the public key from an existing key file as the authorized key.
    ///
    /// The caller is responsible for the private key; `user_key_seed` is set to zeros
    /// because the actual key is managed externally (e.g. by ssh-agent).
    pub fn spawn_with_key_file(user_key_path: &std::path::Path) -> Option<Self> {
        let sshd_path = ["/usr/sbin/sshd", "/usr/bin/sshd", "sshd"]
            .iter()
            .find(|p| std::path::Path::new(p).exists() || which_on_path(p))?
            .to_string();

        let port = free_port()?;
        let dir_path = unique_temp_path("russh_sshd_agent_fixture");
        std::fs::create_dir_all(&dir_path).ok()?;

        // Generate host key.
        let host_key_path = dir_path.join("ssh_host_ed25519_key");
        let ok = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                host_key_path.to_str()?,
                "-N",
                "",
                "-q",
            ])
            .status()
            .ok()?
            .success();
        if !ok {
            return None;
        }
        set_permissions_600(&host_key_path);

        // Copy the public key from the provided key file path.
        let pub_key_content = std::fs::read_to_string(user_key_path.with_extension("pub")).ok()?;

        let auth_keys_path = dir_path.join("authorized_keys");
        std::fs::write(&auth_keys_path, pub_key_content).ok()?;
        set_permissions_600(&auth_keys_path);

        let config_path = dir_path.join("sshd_config");
        let config_text = format!(
            "Port {port}\n\
             HostKey {host_key}\n\
             AuthorizedKeysFile {auth_keys}\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             ChallengeResponseAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             StrictModes no\n\
             PermitRootLogin yes\n\
             AllowUsers {user}\n\
             LogLevel ERROR\n",
            host_key = host_key_path.display(),
            auth_keys = auth_keys_path.display(),
            user = std::env::var("USER").unwrap_or_else(|_| "root".into()),
        );
        std::fs::write(&config_path, config_text).ok()?;

        let mut child = Command::new(&sshd_path)
            .args(["-D", "-f", config_path.to_str()?])
            .spawn()
            .ok()?;

        let ready = wait_for_tcp_ready(port, Some(&mut child), std::time::Duration::from_secs(3));
        if !ready {
            return None;
        }

        Some(SshdFixture {
            port,
            user_key_seed: [0u8; 32],
            _dir: TempPathGuard::new(dir_path),
            child,
        })
    }
}

impl Drop for SshdFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> Option<u16> {
    let listener = StdTcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    drop(listener);
    Some(port)
}

fn wait_for_tcp_ready(
    port: u16,
    mut child: Option<&mut Child>,
    timeout: std::time::Duration,
) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        if let Some(proc) = child.as_mut() {
            if proc.try_wait().ok().flatten().is_some() {
                return false;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    false
}

fn which_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).exists()))
        .unwrap_or(false)
}

#[cfg(unix)]
fn set_permissions_600(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_permissions_600(_path: &std::path::Path) {}

/// Standard (RFC 4648) base64 encode without line wrapping.
fn base64_standard(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(TABLE[b0 >> 2]);
        out.push(TABLE[((b0 & 0x3) << 4) | (b1 >> 4)]);
        out.push(if chunk.len() > 1 {
            TABLE[((b1 & 0xf) << 2) | (b2 >> 6)]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            TABLE[b2 & 0x3f]
        } else {
            b'='
        });
    }
    String::from_utf8(out).expect("base64 output is always valid UTF-8")
}

#[cfg(test)]
#[cfg(unix)]
mod interop_tests {
    use super::{SshdFixture, base64_decode_standard, openssh_available};
    use russh_crypto::{RandomSource, Signer};
    #[cfg(unix)]
    use russh_net::SshAgentClient;
    use russh_net::{
        DefaultSessionHandler, Ed25519Signer, SshClient, SshClientConnection, SshServer,
    };
    use russh_transport::{ClientConfig, ServerConfig};
    use tokio::task;

    /// RuSSH client executes a command on a real OpenSSH sshd.
    #[tokio::test]
    async fn russh_client_exec_against_openssh_sshd() {
        let _guard = super::interop_test_guard().await;
        if !openssh_available() {
            return;
        }
        let fixture = match SshdFixture::spawn() {
            Some(f) => f,
            None => return,
        };

        let addr = format!("127.0.0.1:{}", fixture.port);
        let username = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let mut config = ClientConfig::secure_defaults(&username);
        config.strict_host_key_checking = false;

        let mut conn = SshClientConnection::connect(&addr, config)
            .await
            .expect("connect to sshd");

        let signer = Ed25519Signer::from_seed(&fixture.user_key_seed);
        conn.authenticate_pubkey(&signer)
            .await
            .expect("pubkey auth against sshd");

        let result = conn.exec("echo interop-ok").await.expect("exec");
        assert_eq!(result.stdout, b"interop-ok\n", "exec stdout mismatch");
        assert_eq!(result.exit_code, Some(0));

        conn.disconnect().await.ok();
    }

    /// RuSSH client performs SFTP upload + read-back against a real OpenSSH sshd.
    #[tokio::test]
    async fn russh_client_sftp_against_openssh_sshd() {
        let _guard = super::interop_test_guard().await;
        if !openssh_available() {
            return;
        }
        let fixture = match SshdFixture::spawn() {
            Some(f) => f,
            None => return,
        };

        let addr = format!("127.0.0.1:{}", fixture.port);
        let username = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let mut config = ClientConfig::secure_defaults(&username);
        config.strict_host_key_checking = false;

        let mut conn = SshClientConnection::connect(&addr, config)
            .await
            .expect("connect to sshd for sftp");

        let signer = Ed25519Signer::from_seed(&fixture.user_key_seed);
        conn.authenticate_pubkey(&signer)
            .await
            .expect("pubkey auth for sftp");

        let tmp_path = format!("/tmp/russh_sftp_interop_{}.txt", fixture.port);
        let payload = b"hello from russh sftp";
        {
            let mut sftp = conn.sftp().await.expect("open sftp session");
            sftp.write_file(&tmp_path, payload)
                .await
                .expect("sftp write");
            let read_back = sftp.read_file(&tmp_path).await.expect("sftp read");
            assert_eq!(read_back, payload, "sftp round-trip content mismatch");
            sftp.close().await.ok();
        }

        conn.exec(&format!("rm -f {tmp_path}")).await.ok();
        conn.disconnect().await.ok();
    }

    /// A real OpenSSH `ssh` client executes a command on a RuSSH server.
    #[cfg_attr(
        target_os = "macos",
        ignore = "OpenSSH client closes connection on GitHub macOS runner"
    )]
    #[tokio::test]
    async fn openssh_ssh_exec_against_russh_server() {
        let _guard = super::interop_test_guard().await;
        if !openssh_available() {
            return;
        }

        let tmp = super::unique_temp_path("russh_openssh_exec");
        std::fs::create_dir_all(&tmp).ok();
        let client_key = tmp.join("id_ed25519");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                client_key.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        let server_config = {
            let mut cfg = ServerConfig::secure_defaults();
            cfg.host_key_seed = Some([0x77u8; 32]);
            cfg
        };
        let server = SshServer::bind("127.0.0.1:0", server_config)
            .await
            .expect("bind russh server");
        let port = server.local_addr().expect("get port").port();

        let work_dir = tmp.clone();
        let server_handle = task::spawn(async move {
            if let Ok(conn) = server.accept().await {
                conn.run(DefaultSessionHandler::new(&work_dir)).await.ok();
            }
        });

        tokio::task::yield_now().await;

        let client_key_str = client_key.to_str().unwrap().to_owned();
        let port_str = port.to_string();
        let output = task::spawn_blocking(move || {
            std::process::Command::new("ssh")
                .args([
                    "-i",
                    &client_key_str,
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-p",
                    &port_str,
                    "127.0.0.1",
                    "echo openssh-to-russh",
                ])
                .output()
                .expect("run ssh")
        })
        .await
        .expect("spawn_blocking ssh");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("openssh-to-russh"),
            "expected 'openssh-to-russh' in ssh output, got: {stdout:?}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), server_handle).await;
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A real OpenSSH `sftp` client uploads a file to a RuSSH SFTP server.
    #[cfg_attr(
        target_os = "macos",
        ignore = "OpenSSH client closes connection on GitHub macOS runner"
    )]
    #[tokio::test]
    async fn openssh_sftp_against_russh_server() {
        let _guard = super::interop_test_guard().await;
        if !openssh_available() {
            return;
        }

        let tmp = super::unique_temp_path("russh_openssh_sftp");
        std::fs::create_dir_all(&tmp).ok();
        let client_key = tmp.join("id_ed25519");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                client_key.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        let local_file = tmp.join("upload.txt");
        std::fs::write(&local_file, b"sftp-upload-content").ok();

        let sftp_root = tmp.join("sftp_root");
        std::fs::create_dir_all(&sftp_root).ok();

        let server_config = {
            let mut cfg = ServerConfig::secure_defaults();
            cfg.host_key_seed = Some([0x77u8; 32]);
            cfg
        };
        let server = SshServer::bind("127.0.0.1:0", server_config)
            .await
            .expect("bind russh server for sftp");
        let port = server.local_addr().expect("get port").port();

        let sftp_root_clone = sftp_root.clone();
        let server_handle = task::spawn(async move {
            if let Ok(conn) = server.accept().await {
                conn.run(DefaultSessionHandler::new(&sftp_root_clone))
                    .await
                    .ok();
            }
        });

        tokio::task::yield_now().await;

        // `sftp -b batch_file` uploads using the batch command `put local remote`.
        let batch_cmds = format!("put {} /upload.txt\n", local_file.display());
        let batch_file = tmp.join("sftp_batch");
        std::fs::write(&batch_file, &batch_cmds).ok();

        let client_key_str = client_key.to_str().unwrap().to_owned();
        let batch_file_str = batch_file.to_str().unwrap().to_owned();
        let port_str = port.to_string();
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            task::spawn_blocking(move || {
                std::process::Command::new("sftp")
                    .args([
                        "-i",
                        &client_key_str,
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "PreferredAuthentications=publickey",
                        "-o",
                        "IdentitiesOnly=yes",
                        "-P",
                        &port_str,
                        "-b",
                        &batch_file_str,
                        "127.0.0.1",
                    ])
                    .output()
                    .expect("run sftp")
            }),
        )
        .await
        .expect("sftp timed out after 15 seconds")
        .expect("spawn_blocking sftp");

        assert!(
            output.status.success(),
            "sftp exited non-zero:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        let uploaded = sftp_root.join("upload.txt");
        assert!(
            uploaded.exists(),
            "uploaded file not found at {}",
            uploaded.display()
        );
        assert_eq!(
            std::fs::read(&uploaded).unwrap(),
            b"sftp-upload-content",
            "uploaded file content mismatch"
        );

        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), server_handle).await;
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// RuSSH client authenticates to a real OpenSSH sshd using an OpenSSH certificate.
    ///
    /// Setup:
    /// 1. Generate a CA key with `ssh-keygen`.
    /// 2. Generate a user Ed25519 key pair in memory (RuSSH).
    /// 3. Sign the user public key with the CA using `ssh-keygen -s`.
    /// 4. Configure sshd with `TrustedUserCAKeys`.
    /// 5. Authenticate with `authenticate_pubkey_with_cert`.
    #[tokio::test]
    async fn russh_cert_auth_against_openssh_sshd() {
        let _guard = super::interop_test_guard().await;
        if !openssh_available() {
            return;
        }

        let tmp = super::unique_temp_path("russh_cert_auth");
        std::fs::create_dir_all(&tmp).ok();

        // Generate CA key.
        let ca_key_path = tmp.join("ca_key");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                ca_key_path.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        // Generate user key using russh-crypto.
        let mut seed = [0u8; 32];
        russh_crypto::OsRng.fill_bytes(&mut seed);
        let user_signer = Ed25519Signer::from_seed(&seed);
        let public_key_blob = user_signer.public_key_blob();

        // Write user public key in OpenSSH format so ssh-keygen can sign it.
        let user_pubkey_path = tmp.join("user_key.pub");
        let user_pub_line = format!(
            "ssh-ed25519 {} russh-test-user\n",
            super::base64_standard(&public_key_blob)
        );
        std::fs::write(&user_pubkey_path, &user_pub_line).ok();

        // Sign the user public key with the CA.
        let username = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let cert_path = tmp.join("user_key-cert.pub");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-s",
                ca_key_path.to_str().unwrap(),
                "-I",
                "russh-test",
                "-n",
                &username,
                "-V",
                "always:forever",
                user_pubkey_path.to_str().unwrap(),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok || !cert_path.exists() {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        // Parse the cert blob from the -cert.pub file (format: "<keytype> <base64> <comment>").
        let cert_file = std::fs::read_to_string(&cert_path).unwrap_or_default();
        let cert_b64 = cert_file.split_whitespace().nth(1).unwrap_or("").to_owned();
        if cert_b64.is_empty() {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
        let cert_blob = base64_decode_standard(&cert_b64);

        // Read the CA public key blob for the sshd TrustedUserCAKeys file.
        let ca_pub_path = tmp.join("ca_key.pub");

        // Write sshd config with TrustedUserCAKeys.
        let host_key_path = tmp.join("ssh_host_ed25519_key");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                host_key_path.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
        super::set_permissions_600(&host_key_path);

        // Empty authorized_keys (cert auth uses TrustedUserCAKeys instead).
        let auth_keys_path = tmp.join("authorized_keys");
        std::fs::write(&auth_keys_path, b"").ok();
        super::set_permissions_600(&auth_keys_path);

        let port = match super::free_port() {
            Some(p) => p,
            None => return,
        };

        let config_path = tmp.join("sshd_config");
        let config_text = format!(
            "Port {port}\n\
             HostKey {host_key}\n\
             AuthorizedKeysFile {auth_keys}\n\
             TrustedUserCAKeys {ca_pub}\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             ChallengeResponseAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             StrictModes no\n\
             PermitRootLogin yes\n\
             AllowUsers {user}\n\
             LogLevel ERROR\n",
            host_key = host_key_path.display(),
            auth_keys = auth_keys_path.display(),
            ca_pub = ca_pub_path.display(),
            user = username,
        );
        std::fs::write(&config_path, &config_text).ok();

        let sshd_path = ["/usr/sbin/sshd", "/usr/bin/sshd"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .copied()
            .unwrap_or("sshd");
        let mut sshd = match std::process::Command::new(sshd_path)
            .args(["-D", "-f", config_path.to_str().unwrap()])
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&tmp);
                return;
            }
        };

        // Wait for sshd to be ready.
        let ready =
            super::wait_for_tcp_ready(port, Some(&mut sshd), std::time::Duration::from_secs(3));
        if !ready {
            let _ = sshd.kill();
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        // Connect and authenticate with the cert.
        let addr = format!("127.0.0.1:{port}");
        let mut config = ClientConfig::secure_defaults(&username);
        config.strict_host_key_checking = false;

        let mut conn = match SshClientConnection::connect(&addr, config).await {
            Ok(c) => c,
            Err(e) => {
                let _ = sshd.kill();
                let _ = std::fs::remove_dir_all(&tmp);
                panic!("connect failed: {e}");
            }
        };

        conn.authenticate_pubkey_with_cert(cert_blob, &user_signer)
            .await
            .expect("cert authentication should succeed");

        let result = conn.exec("echo cert-auth-ok").await.expect("exec");
        assert_eq!(result.stdout, b"cert-auth-ok\n", "exec stdout mismatch");

        conn.disconnect().await.ok();
        let _ = sshd.kill();
        let _ = sshd.wait();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// An OpenSSH `ssh` client authenticates to a RuSSH server using an OpenSSH certificate.
    ///
    /// RuSSH validates the CA signature and accepts the connection.
    #[cfg_attr(
        target_os = "macos",
        ignore = "OpenSSH client closes connection on GitHub macOS runner"
    )]
    #[tokio::test]
    async fn openssh_cert_auth_against_russh_server() {
        let _guard = super::interop_test_guard().await;
        if !openssh_available() {
            return;
        }

        let tmp = super::unique_temp_path("russh_russh_cert");
        std::fs::create_dir_all(&tmp).ok();

        // Generate CA key.
        let ca_key_path = tmp.join("ca_key");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                ca_key_path.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        // Read CA public key blob for the cert validator.
        let ca_pub_line = std::fs::read_to_string(tmp.join("ca_key.pub")).unwrap_or_default();
        let ca_b64 = ca_pub_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_owned();
        if ca_b64.is_empty() {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
        // The CA blob from OpenSSH format is a raw Ed25519 public key blob.
        let ca_key_blob = base64_decode_standard(&ca_b64);

        // Generate a user key for the OpenSSH client.
        let user_key_path = tmp.join("user_key");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                user_key_path.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
        super::set_permissions_600(&user_key_path);

        // Sign the user key with the CA.
        let username = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let cert_path = tmp.join("user_key-cert.pub");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-s",
                ca_key_path.to_str().unwrap(),
                "-I",
                "russh-test",
                "-n",
                &username,
                "-V",
                "always:forever",
                user_key_path.with_extension("pub").to_str().unwrap(),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok || !cert_path.exists() {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        // Configure RuSSH server with a cert validator trusting the CA.
        let server_config = {
            use russh_auth::{CertificateValidator, ServerAuthPolicy};
            let mut policy = ServerAuthPolicy::secure_defaults();
            let validator = CertificateValidator::permissive().trust_ca_key(ca_key_blob);
            policy.set_certificate_validator(validator);
            let mut cfg = ServerConfig::secure_defaults();
            cfg.host_key_seed = Some([0xAAu8; 32]);
            cfg.auth_policy = Some(policy);
            cfg
        };

        let server = SshServer::bind("127.0.0.1:0", server_config)
            .await
            .expect("bind russh server");
        let port = server.local_addr().expect("get port").port();

        let work_dir = tmp.clone();
        let server_handle = task::spawn(async move {
            if let Ok(conn) = server.accept().await {
                conn.run(DefaultSessionHandler::new(&work_dir)).await.ok();
            }
        });

        tokio::task::yield_now().await;

        let user_key_str = user_key_path.to_str().unwrap().to_owned();
        let cert_str = cert_path.to_str().unwrap().to_owned();
        let port_str = port.to_string();
        let output = task::spawn_blocking(move || {
            std::process::Command::new("ssh")
                .args([
                    "-i",
                    &user_key_str,
                    "-i",
                    &cert_str,
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-p",
                    &port_str,
                    "127.0.0.1",
                    "echo openssh-cert-to-russh",
                ])
                .output()
                .expect("run ssh")
        })
        .await
        .expect("spawn_blocking ssh");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("openssh-cert-to-russh"),
            "expected output in ssh stdout, got: {stdout:?}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );

        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), server_handle).await;
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// RuSSH client authenticates to a real OpenSSH sshd using an SSH agent (`ssh-agent`).
    ///
    /// Setup:
    /// 1. Start `ssh-agent` and capture `SSH_AUTH_SOCK`.
    /// 2. Generate a user key and add it with `ssh-add`.
    /// 3. Spawn sshd with the user's public key in `authorized_keys`.
    /// 4. Authenticate via `SshAgentClient::from_env()` + `authenticate_via_agent`.
    #[cfg(unix)]
    #[tokio::test]
    async fn russh_agent_auth_against_openssh_sshd() {
        let _guard = super::interop_test_guard().await;
        if !openssh_available() {
            return;
        }
        // Check that ssh-agent is available.
        if !std::path::Path::new("/usr/bin/ssh-agent").exists()
            && !std::path::Path::new("/bin/ssh-agent").exists()
        {
            return;
        }

        let tmp = super::unique_temp_path("russh_agent_auth");
        std::fs::create_dir_all(&tmp).ok();

        // Generate user key.
        let user_key_path = tmp.join("id_ed25519");
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                user_key_path.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
        super::set_permissions_600(&user_key_path);

        // Start ssh-agent in foreground mode (-D) with a known socket path.
        let agent_sock = tmp.join("agent.sock");
        let mut agent_proc = match std::process::Command::new("ssh-agent")
            .args(["-D", "-a", agent_sock.to_str().unwrap()])
            .spawn()
        {
            Ok(p) => p,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&tmp);
                return;
            }
        };

        // Wait for socket to appear.
        let ready = (0..30).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            agent_sock.exists()
        });
        if !ready {
            let _ = agent_proc.kill();
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        // Add the user key to the agent.
        let ok = std::process::Command::new("ssh-add")
            .arg(user_key_path.to_str().unwrap())
            .env("SSH_AUTH_SOCK", agent_sock.to_str().unwrap())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = agent_proc.kill();
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }

        // Spawn sshd with the user's public key.
        let fixture = match SshdFixture::spawn_with_key_file(&user_key_path) {
            Some(f) => f,
            None => {
                let _ = agent_proc.kill();
                let _ = std::fs::remove_dir_all(&tmp);
                return;
            }
        };

        // Authenticate via agent.
        let addr = format!("127.0.0.1:{}", fixture.port);
        let username = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let mut config = ClientConfig::secure_defaults(&username);
        config.strict_host_key_checking = false;

        let mut conn = match SshClientConnection::connect(&addr, config).await {
            Ok(c) => c,
            Err(e) => {
                let _ = agent_proc.kill();
                let _ = std::fs::remove_dir_all(&tmp);
                panic!("connect failed: {e}");
            }
        };

        let agent = SshAgentClient::new(agent_sock.to_str().unwrap());
        conn.authenticate_via_agent(&agent)
            .await
            .expect("agent authentication should succeed");

        let result = conn.exec("echo agent-auth-ok").await.expect("exec");
        assert_eq!(result.stdout, b"agent-auth-ok\n", "exec stdout mismatch");

        conn.disconnect().await.ok();
        let _ = agent_proc.kill();
        let _ = agent_proc.wait();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// RuSSH client connects to a target sshd via a ProxyJump (direct-tcpip).
    ///
    /// Spawns two sshd instances (jump_port, target_port).  RuSSH connects to
    /// the target through the jump host using `SshClient::connect_via_jump`.
    #[tokio::test]
    async fn russh_proxyjump_through_openssh_sshd() {
        let _guard = super::interop_test_guard().await;
        if !openssh_available() {
            return;
        }

        // Spawn the jump sshd (same key pair for simplicity).
        let jump_fixture = match SshdFixture::spawn() {
            Some(f) => f,
            None => return,
        };

        // Spawn the target sshd with the same key.
        // Reuse the jump fixture's user key by writing it as a .pub file for the target sshd.
        let tmp_pub = super::unique_temp_path("russh_pj_pub").with_extension("pub");
        {
            let signer_tmp = Ed25519Signer::from_seed(&jump_fixture.user_key_seed);
            let pub_line = format!(
                "ssh-ed25519 {} russh-proxyjump-test\n",
                super::base64_standard(&signer_tmp.public_key_blob())
            );
            std::fs::write(&tmp_pub, &pub_line).ok();
        }
        let target_fixture = match SshdFixture::spawn_with_key_file(&tmp_pub) {
            Some(f) => f,
            None => return,
        };

        let jump_port = jump_fixture.port;
        let target_port = target_fixture.port;

        let username = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let signer = Ed25519Signer::from_seed(&jump_fixture.user_key_seed);
        let seed_copy = jump_fixture.user_key_seed;

        let mut jump_cfg = ClientConfig::secure_defaults(&username);
        jump_cfg.strict_host_key_checking = false;

        let mut target_cfg = ClientConfig::secure_defaults(&username);
        target_cfg.strict_host_key_checking = false;

        let mut conn = SshClient::connect_via_jump(
            format!("127.0.0.1:{jump_port}"),
            jump_cfg,
            |jump_conn| {
                let s = Ed25519Signer::from_seed(&seed_copy);
                Box::pin(async move { jump_conn.authenticate_pubkey(&s).await })
            },
            "127.0.0.1",
            target_port,
            target_cfg,
        )
        .await
        .expect("connect_via_jump should succeed");

        conn.authenticate_pubkey(&signer)
            .await
            .expect("target auth should succeed");

        let result = conn.exec("echo proxyjump-ok").await.expect("exec");
        assert_eq!(
            result.stdout, b"proxyjump-ok\n",
            "proxyjump exec stdout mismatch"
        );

        conn.disconnect().await.ok();

        // Clean up temp pub file.
        let _ = std::fs::remove_file(&tmp_pub);
    }
}

/// Decode a standard Base64 string (RFC 4648) into bytes.
#[allow(dead_code)]
fn base64_decode_standard(s: &str) -> Vec<u8> {
    const DECODE: [u8; 256] = {
        let mut t = [0xFFu8; 256];
        let src = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0usize;
        while i < 64 {
            t[src[i] as usize] = i as u8;
            i += 1;
        }
        t
    };
    let s = s.as_bytes();
    let len = s.iter().filter(|&&b| b != b'=').count();
    let mut out = Vec::with_capacity((len * 6).div_ceil(8));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in s {
        if b == b'=' {
            break;
        }
        let v = DECODE[b as usize];
        if v == 0xFF {
            continue;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}
