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
            .args(["-t", "ed25519", "-f", host_key_path.to_str()?, "-N", "", "-q"])
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
        let auth_key_line = format!("ssh-ed25519 {} russh-test\n", base64_standard(&public_key_blob));
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
             Subsystem sftp /usr/lib/openssh/sftp-server\n",
            host_key = host_key_path.display(),
            auth_keys = auth_keys_path.display(),
            user = std::env::var("USER").unwrap_or_else(|_| "root".into()),
        );
        std::fs::write(&config_path, config_text).ok()?;

        // Spawn sshd in foreground mode.
        let child = Command::new(&sshd_path)
            .args(["-D", "-f", config_path.to_str()?])
            .spawn()
            .ok()?;

        // Wait up to 3 s for the port to accept connections.
        let ready = (0..30).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        });
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

fn which_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).exists()))
        .unwrap_or(false)
}

fn set_permissions_600(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// Standard (RFC 4648) base64 encode without line wrapping.
fn base64_standard(input: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        out.push(TABLE[b0 >> 2]);
        out.push(TABLE[((b0 & 0x3) << 4) | (b1 >> 4)]);
        out.push(if chunk.len() > 1 { TABLE[((b1 & 0xf) << 2) | (b2 >> 6)] } else { b'=' });
        out.push(if chunk.len() > 2 { TABLE[b2 & 0x3f] } else { b'=' });
    }
    String::from_utf8(out).expect("base64 output is always valid UTF-8")
}

#[cfg(test)]
mod interop_tests {
    use super::{SshdFixture, openssh_available};
    use russh_net::{DefaultSessionHandler, Ed25519Signer, SshClientConnection, SshServer};
    use russh_transport::{ClientConfig, ServerConfig};
    use tokio::task;

    /// RuSSH client executes a command on a real OpenSSH sshd.
    #[tokio::test]
    async fn russh_client_exec_against_openssh_sshd() {
        if !openssh_available() {
            return;
        }
        let fixture = match SshdFixture::spawn() {
            Some(f) => f,
            None => return,
        };

        let addr = format!("127.0.0.1:{}", fixture.port);
        let mut config = ClientConfig::secure_defaults("root");
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
        if !openssh_available() {
            return;
        }
        let fixture = match SshdFixture::spawn() {
            Some(f) => f,
            None => return,
        };

        let addr = format!("127.0.0.1:{}", fixture.port);
        let mut config = ClientConfig::secure_defaults("root");
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
            sftp.write_file(&tmp_path, payload).await.expect("sftp write");
            let read_back = sftp.read_file(&tmp_path).await.expect("sftp read");
            assert_eq!(read_back, payload, "sftp round-trip content mismatch");
            sftp.close().await.ok();
        }

        conn.exec(&format!("rm -f {tmp_path}")).await.ok();
        conn.disconnect().await.ok();
    }

    /// A real OpenSSH `ssh` client executes a command on a RuSSH server.
    #[tokio::test]
    async fn openssh_ssh_exec_against_russh_server() {
        if !openssh_available() {
            return;
        }

        let tmp = std::env::temp_dir()
            .join(format!("russh_openssh_exec_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();
        let client_key = tmp.join("id_ed25519");
        let ok = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f", client_key.to_str().unwrap(), "-N", "", "-q"])
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

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let client_key_str = client_key.to_str().unwrap().to_owned();
        let port_str = port.to_string();
        let output = task::spawn_blocking(move || {
            std::process::Command::new("ssh")
                .args([
                    "-i", &client_key_str,
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    "-o", "PreferredAuthentications=publickey",
                    "-p", &port_str,
                    "127.0.0.1",
                    "echo openssh-to-russh",
                ])
                .output()
                .expect("run ssh")
        }).await.expect("spawn_blocking ssh");

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
    #[tokio::test]
    async fn openssh_sftp_against_russh_server() {
        if !openssh_available() {
            return;
        }

        let tmp = std::env::temp_dir()
            .join(format!("russh_openssh_sftp_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();
        let client_key = tmp.join("id_ed25519");
        let ok = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f", client_key.to_str().unwrap(), "-N", "", "-q"])
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
                conn.run(DefaultSessionHandler::new(&sftp_root_clone)).await.ok();
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

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
                        "-i", &client_key_str,
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "BatchMode=yes",
                        "-o", "PreferredAuthentications=publickey",
                        "-P", &port_str,
                        "-b", &batch_file_str,
                        "127.0.0.1",
                    ])
                    .output()
                    .expect("run sftp")
            })
        ).await
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
}

