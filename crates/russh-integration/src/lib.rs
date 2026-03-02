//! Integration harness primitives and smoke scenarios.

use std::future::ready;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use russh_auth::{AuthEngine, AuthRequest, ServerAuthPolicy};
use russh_channel::{Channel, ChannelKind, ConnectionPool};
use russh_config::parse_config;
use russh_core::{
    AlgorithmSet, PacketCodec, PacketFrame, PacketParser, RusshError, RusshErrorCategory,
};
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
}
