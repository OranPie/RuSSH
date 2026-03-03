//! russh-web — browser-based SSH terminal over WebSocket.
//!
//! Serves a single-page xterm.js terminal that connects to any SSH server
//! via RuSSH.  Communication flows:
//!
//! ```text
//! Browser ←[WebSocket]→ russh-web ←[SSH]→ target server
//! ```
//!
//! ## Protocol
//!
//! The WebSocket carries JSON messages for the setup phase and raw binary
//! frames for terminal I/O:
//!
//! 1. Client sends `{"type":"connect","host":"...","port":22,"user":"...","password":"..."}`
//! 2. Server replies `{"type":"connected"}` on success, or `{"type":"error","message":"..."}`
//! 3. After that, binary frames flow bidirectionally (terminal data).

use std::sync::Arc;

use axum::{
    Router,
    extract::WebSocketUpgrade,
    extract::ws::{Message, WebSocket},
    response::{Html, IntoResponse},
    routing::get,
};
use russh_crypto::Ed25519Signer;
use russh_net::SshClientConnection;
use russh_observability::{Severity, StderrLogger};
use russh_transport::ClientConfig;
use serde::Deserialize;

/// Embedded HTML/JS page with xterm.js terminal.
pub const INDEX_HTML: &str = include_str!("index.html");

/// Build the axum router.
pub fn app(log: Arc<StderrLogger>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ws", get(move |ws| ws_handler(ws, log)))
}

async fn index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

#[derive(Deserialize)]
struct ConnectRequest {
    host: String,
    port: Option<u16>,
    user: String,
    password: Option<String>,
    #[serde(default)]
    identity_seed_hex: Option<String>,
}

async fn ws_handler(ws: WebSocketUpgrade, log: Arc<StderrLogger>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, log))
}

/// Send a JSON error message over the WebSocket.
async fn send_error(socket: &mut WebSocket, msg: &str) {
    let payload: String = format!(r#"{{"type":"error","message":"{msg}"}}"#);
    let _ = socket.send(Message::Text(payload.into())).await;
}

async fn handle_socket(mut socket: WebSocket, log: Arc<StderrLogger>) {
    // Phase 1: wait for connect request (JSON text message).
    let connect_req: ConnectRequest = loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => match serde_json::from_str::<ConnectRequest>(&text) {
                Ok(req) => break req,
                Err(e) => {
                    send_error(&mut socket, &format!("bad request: {e}")).await;
                    return;
                }
            },
            Some(Ok(_)) => continue,
            _ => return,
        }
    };

    let port = connect_req.port.unwrap_or(22);
    let addr = format!("{}:{port}", connect_req.host);
    log.log(
        Severity::Info,
        &format!("ws: connecting to {addr} as {}", connect_req.user),
    );

    // Phase 2: establish SSH connection.
    let cfg = ClientConfig::secure_defaults(&connect_req.user);
    let mut conn = match SshClientConnection::connect(&addr, cfg).await {
        Ok(c) => c,
        Err(e) => {
            send_error(&mut socket, &format!("connect failed: {e}")).await;
            return;
        }
    };

    // Phase 3: authenticate.
    let authed = if let Some(hex) = &connect_req.identity_seed_hex {
        if let Ok(seed_bytes) = hex_decode(hex) {
            if seed_bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                let signer = Ed25519Signer::from_seed(&seed);
                conn.authenticate_pubkey(&signer).await.is_ok()
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    if !authed {
        if let Some(pw) = &connect_req.password {
            if let Err(e) = conn.authenticate_password(pw).await {
                send_error(&mut socket, &format!("auth failed: {e}")).await;
                return;
            }
        } else {
            send_error(&mut socket, "no credentials provided").await;
            return;
        }
    }

    log.log(
        Severity::Info,
        &format!("ws: authenticated as {}", connect_req.user),
    );

    // Phase 4: open interactive shell.
    let (_local_id, remote_id) = match conn.open_shell("xterm-256color", 80, 24).await {
        Ok(ids) => ids,
        Err(e) => {
            send_error(&mut socket, &format!("shell failed: {e}")).await;
            return;
        }
    };

    let _ = socket
        .send(Message::Text(r#"{"type":"connected"}"#.into()))
        .await;

    log.log(Severity::Debug, "ws: shell opened, starting relay");

    // Phase 5: bidirectional relay via channel-backed AsyncRead / AsyncWrite.
    //
    // Two mpsc channels bridge the WebSocket and the SSH session:
    //   browser_tx/browser_rx : browser keystrokes → ChannelReader → SSH input
    //   ssh_tx/ssh_rx         : SSH output → ChannelWriter → WebSocket
    //
    // A single background task owns the WebSocket and multiplexes reads
    // and writes through a `tokio::select!` loop.

    let (browser_tx, browser_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (ssh_tx, mut ssh_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Background task: WebSocket ↔ mpsc bridge.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = socket.recv() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            if browser_tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Text(text))) => {
                            if browser_tx.send(text.to_string().into_bytes()).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        _ => {}
                    }
                }
                data = ssh_rx.recv() => {
                    match data {
                        Some(bytes) => {
                            if socket.send(Message::Binary(bytes.into())).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // Channel-backed I/O adapters for run_shell_session.
    let mut input = ChannelReader::new(browser_rx);
    let mut output = ChannelWriter::new(ssh_tx);

    let exit_code = conn
        .run_shell_session(remote_id, &mut input, &mut output)
        .await
        .unwrap_or(0);

    log.log(
        Severity::Info,
        &format!("ws: session ended (exit={exit_code})"),
    );
    // Dropping `output` closes ssh_tx, which ends the background task.
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Adapter: mpsc::Receiver<Vec<u8>> → AsyncRead
struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl tokio::io::AsyncRead for ChannelReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Serve from leftover buffer first.
        if self.pos < self.buf.len() {
            let n = std::cmp::min(buf.remaining(), self.buf.len() - self.pos);
            buf.put_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos >= self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        // Try to receive new data.
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.buf = data;
                    self.pos = n;
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Adapter: mpsc::Sender<Vec<u8>> → AsyncWrite
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl ChannelWriter {
    fn new(tx: tokio::sync::mpsc::Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

impl tokio::io::AsyncWrite for ChannelWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.tx.try_send(buf.to_vec()) {
            Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => std::task::Poll::Pending,
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "channel closed",
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
