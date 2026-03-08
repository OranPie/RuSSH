use std::cell::RefCell;
use std::pin::Pin;
use std::task::{Context, Poll};

use js_sys::{ArrayBuffer, Function, JsString, Uint8Array};
use russh_auth::{
    UserAuthMessage, UserAuthRequest, build_ed25519_signature_blob, build_userauth_signing_payload,
};
use russh_channel::{ChannelKind, ChannelManager, ChannelMessage, ChannelRequest};
use russh_core::{PacketCodec, PacketFrame, RusshError, RusshErrorCategory};
use russh_crypto::{AeadCipher, Aes256GcmCipher, Ed25519Signer, Signer};
use russh_transport::{
    ClientConfig, ClientSession, NegotiatedAlgorithms, SessionKeys, TransportMessage,
};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{BinaryType, CloseEvent, ErrorEvent, Event, MessageEvent, WebSocket};

const OUR_BANNER: &str = "SSH-2.0-RuSSH_0.4";

#[derive(Clone)]
struct Callbacks {
    status: Function,
    info: Function,
    error: Function,
    binary: Function,
}

struct ClientState {
    ws: Option<WebSocket>,
    mode: String,
    is_connected: bool,
    is_connecting: bool,
    callbacks: Option<Callbacks>,
    input_tx: Option<mpsc::Sender<Vec<u8>>>,
    on_open: Option<Closure<dyn FnMut(Event)>>,
    on_message: Option<Closure<dyn FnMut(MessageEvent)>>,
    on_error: Option<Closure<dyn FnMut(ErrorEvent)>>,
    on_close: Option<Closure<dyn FnMut(CloseEvent)>>,
}

impl ClientState {
    fn new() -> Self {
        Self {
            ws: None,
            mode: "".into(),
            is_connected: false,
            is_connecting: false,
            callbacks: None,
            input_tx: None,
            on_open: None,
            on_message: None,
            on_error: None,
            on_close: None,
        }
    }

    fn clear_ws(&mut self) {
        self.ws = None;
        self.input_tx = None;
        self.on_open = None;
        self.on_message = None;
        self.on_error = None;
        self.on_close = None;
    }
}

thread_local! {
    static CLIENT: RefCell<ClientState> = RefCell::new(ClientState::new());
}

#[derive(Deserialize)]
struct BridgeMessage {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    message: String,
}

fn emit_status(tag: &str) {
    CLIENT.with(|cell| {
        let cb = cell.borrow().callbacks.clone();
        if let Some(cbs) = cb {
            let _ = cbs.status.call1(&JsValue::NULL, &JsValue::from_str(tag));
        }
    });
}

fn emit_info(line: &str) {
    CLIENT.with(|cell| {
        let cb = cell.borrow().callbacks.clone();
        if let Some(cbs) = cb {
            let _ = cbs.info.call1(&JsValue::NULL, &JsValue::from_str(line));
        }
    });
}

fn emit_error(line: &str) {
    CLIENT.with(|cell| {
        let cb = cell.borrow().callbacks.clone();
        if let Some(cbs) = cb {
            let _ = cbs.error.call1(&JsValue::NULL, &JsValue::from_str(line));
        }
    });
}

fn emit_binary(bytes: &[u8]) {
    CLIENT.with(|cell| {
        let cb = cell.borrow().callbacks.clone();
        if let Some(cbs) = cb {
            let arr = Uint8Array::from(bytes);
            let _ = cbs.binary.call1(&JsValue::NULL, &arr.into());
        }
    });
}

fn set_state(mode: &str, connecting: bool, connected: bool) {
    CLIENT.with(|cell| {
        let mut state = cell.borrow_mut();
        state.mode = mode.to_string();
        state.is_connecting = connecting;
        state.is_connected = connected;
    });
}

fn close_current_ws() {
    CLIENT.with(|cell| {
        let mut state = cell.borrow_mut();
        if let Some(ws) = &state.ws {
            let _ = ws.close();
        }
        state.mode.clear();
        state.is_connected = false;
        state.is_connecting = false;
        state.clear_ws();
    });
}

#[wasm_bindgen]
pub fn init_client(status: Function, info: Function, error: Function, binary: Function) {
    CLIENT.with(|cell| {
        let mut state = cell.borrow_mut();
        state.callbacks = Some(Callbacks {
            status,
            info,
            error,
            binary,
        });
    });
}

#[wasm_bindgen]
pub async fn connect(
    mode: String,
    ws_url: String,
    host: String,
    port: u16,
    user: String,
    password: String,
    identity_seed_hex: String,
) -> Result<(), JsValue> {
    if ws_url.trim().is_empty() || host.trim().is_empty() {
        return Err(JsValue::from_str("ws_url and host are required"));
    }
    if mode == "legacy" && user.trim().is_empty() {
        return Err(JsValue::from_str("user is required in legacy mode"));
    }

    close_current_ws();
    emit_status("connecting");
    emit_info(&format!("[RuSSH WASM] connecting via {ws_url} mode={mode}"));

    let ws = WebSocket::new(&ws_url)?;
    ws.set_binary_type(BinaryType::Arraybuffer);

    if mode == "legacy" {
        connect_legacy(ws, &host, port, &user, &password, &identity_seed_hex)?;
        set_state(&mode, true, false);
        return Ok(());
    }

    connect_tunnel(ws, &host, port, &user, &password, &identity_seed_hex).await?;
    Ok(())
}

fn connect_legacy(
    ws: WebSocket,
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    identity_seed_hex: &str,
) -> Result<(), JsValue> {
    let req_json = serde_json::to_string(&serde_json::json!({
        "type": "connect",
        "host": host,
        "port": port,
        "user": user,
        "password": if password.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(password.to_string()) },
        "identity_seed_hex": if identity_seed_hex.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(identity_seed_hex.to_string()) },
    }))
    .map_err(|e| JsValue::from_str(&format!("serialize connect request failed: {e}")))?;

    let ws_for_open = ws.clone();
    let req_for_open = req_json.clone();
    let on_open = Closure::wrap(Box::new(move |_event: Event| {
        if let Err(e) = ws_for_open.send_with_str(&req_for_open) {
            emit_error(&format!("send connect request failed: {e:?}"));
            close_current_ws();
            emit_status("error");
        }
    }) as Box<dyn FnMut(_)>);

    let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
        let data = event.data();
        if let Some(txt) = data.dyn_ref::<JsString>() {
            let raw = txt.as_string().unwrap_or_default();
            if let Ok(msg) = serde_json::from_str::<BridgeMessage>(&raw) {
                match msg.kind.as_str() {
                    "connected" => {
                        set_state("legacy", false, true);
                        emit_status("connected");
                        emit_info("[RuSSH WASM] legacy session ready");
                    }
                    "error" => {
                        set_state("legacy", false, false);
                        emit_status("error");
                        emit_error(&msg.message);
                    }
                    _ => emit_info(&raw),
                }
            }
            return;
        }

        if let Some(buf) = data.dyn_ref::<ArrayBuffer>() {
            emit_binary(&Uint8Array::new(buf).to_vec());
        }
    }) as Box<dyn FnMut(_)>);

    let on_error = Closure::wrap(Box::new(move |_event: ErrorEvent| {
        set_state("legacy", false, false);
        emit_status("error");
        emit_error("websocket error");
    }) as Box<dyn FnMut(_)>);

    let on_close = Closure::wrap(Box::new(move |_event: CloseEvent| {
        set_state("legacy", false, false);
        emit_status("disconnected");
        emit_info("[RuSSH WASM] connection closed");
    }) as Box<dyn FnMut(_)>);

    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    CLIENT.with(|cell| {
        let mut state = cell.borrow_mut();
        state.ws = Some(ws);
        state.mode = "legacy".into();
        state.is_connecting = true;
        state.is_connected = false;
        state.on_open = Some(on_open);
        state.on_message = Some(on_message);
        state.on_error = Some(on_error);
        state.on_close = Some(on_close);
    });

    Ok(())
}

async fn connect_tunnel(
    ws: WebSocket,
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    identity_seed_hex: &str,
) -> Result<(), JsValue> {
    let connect_tcp_json = serde_json::to_string(&serde_json::json!({
        "type": "connect_tcp",
        "host": host,
        "port": port,
    }))
    .map_err(|e| JsValue::from_str(&format!("serialize tunnel request failed: {e}")))?;

    let (tcp_rx_tx, tcp_rx) = mpsc::channel::<Vec<u8>>(256);
    let (ctl_tx, mut ctl_rx) = mpsc::channel::<Result<(), String>>(4);

    let ws_for_open = ws.clone();
    let req_for_open = connect_tcp_json.clone();
    let on_open = Closure::wrap(Box::new(move |_event: Event| {
        if let Err(e) = ws_for_open.send_with_str(&req_for_open) {
            emit_error(&format!("send tunnel request failed: {e:?}"));
        }
    }) as Box<dyn FnMut(_)>);

    let ctl_for_msg = ctl_tx.clone();
    let tcp_for_msg = tcp_rx_tx.clone();
    let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
        let data = event.data();
        if let Some(txt) = data.dyn_ref::<JsString>() {
            let raw = txt.as_string().unwrap_or_default();
            if let Ok(msg) = serde_json::from_str::<BridgeMessage>(&raw) {
                match msg.kind.as_str() {
                    "connected" => {
                        let _ = ctl_for_msg.try_send(Ok(()));
                    }
                    "error" => {
                        let _ = ctl_for_msg.try_send(Err(if msg.message.is_empty() { "bridge error".into() } else { msg.message }));
                    }
                    _ => emit_info(&raw),
                }
            }
            return;
        }
        if let Some(buf) = data.dyn_ref::<ArrayBuffer>() {
            let _ = tcp_for_msg.try_send(Uint8Array::new(buf).to_vec());
        }
    }) as Box<dyn FnMut(_)>);

    let ctl_for_err = ctl_tx.clone();
    let on_error = Closure::wrap(Box::new(move |_event: ErrorEvent| {
        let _ = ctl_for_err.try_send(Err("websocket error".into()));
    }) as Box<dyn FnMut(_)>);

    let on_close = Closure::wrap(Box::new(move |_event: CloseEvent| {
        emit_status("disconnected");
        set_state("tunnel", false, false);
    }) as Box<dyn FnMut(_)>);

    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    CLIENT.with(|cell| {
        let mut state = cell.borrow_mut();
        state.ws = Some(ws.clone());
        state.mode = "tunnel".into();
        state.is_connecting = true;
        state.is_connected = false;
        state.on_open = Some(on_open);
        state.on_message = Some(on_message);
        state.on_error = Some(on_error);
        state.on_close = Some(on_close);
    });

    match ctl_rx.recv().await {
        Some(Ok(())) => {}
        Some(Err(e)) => {
            set_state("tunnel", false, false);
            emit_status("error");
            return Err(JsValue::from_str(&e));
        }
        None => {
            set_state("tunnel", false, false);
            return Err(JsValue::from_str("tunnel setup failed"));
        }
    }

    let tunnel_stream = WsTunnelStream::new(ws, tcp_rx);
    let cfg = ClientConfig::secure_defaults(user);
    let mut conn = BrowserSshClient::connect_via_stream(Box::new(tunnel_stream), cfg)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    if !identity_seed_hex.is_empty() {
        if let Ok(seed_bytes) = hex_decode(identity_seed_hex) {
            if seed_bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                let signer = Ed25519Signer::from_seed(&seed);
                if conn.authenticate_pubkey(&signer).await.is_err() {
                    if !password.is_empty() {
                        conn.authenticate_password(password)
                            .await
                            .map_err(|e| JsValue::from_str(&e.to_string()))?;
                    }
                }
            }
        }
    } else if !password.is_empty() {
        conn.authenticate_password(password)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    } else {
        return Err(JsValue::from_str(
            "tunnel mode requires password or identity seed",
        ));
    }

    let (local_id, remote_id) = conn
        .open_shell("xterm-256color", 80, 24)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(256);
    CLIENT.with(|cell| {
        let mut state = cell.borrow_mut();
        state.input_tx = Some(input_tx);
        state.is_connecting = false;
        state.is_connected = true;
    });
    emit_status("connected");
    emit_info("[RuSSH WASM] tunnel SSH session ready");

    spawn_local(async move {
        let mut input = ChannelReader::new(input_rx);
        let mut output = CallbackWriter;
        let _ = conn
            .run_shell_session(local_id, remote_id, &mut input, &mut output)
            .await;
        set_state("tunnel", false, false);
        emit_status("disconnected");
        emit_info("[RuSSH WASM] tunnel SSH session closed");
    });

    Ok(())
}

#[wasm_bindgen]
pub async fn send_input(bytes: Vec<u8>) -> Result<(), JsValue> {
    let mode = CLIENT.with(|cell| cell.borrow().mode.clone());
    if mode == "legacy" {
        return CLIENT.with(|cell| {
            let state = cell.borrow();
            let ws = state
                .ws
                .as_ref()
                .ok_or_else(|| JsValue::from_str("not connected"))?;
            if ws.ready_state() != WebSocket::OPEN {
                return Err(JsValue::from_str("websocket is not open"));
            }
            ws.send_with_u8_array(&bytes)
        });
    }

    let tx = CLIENT.with(|cell| cell.borrow().input_tx.clone());
    match tx {
        Some(tx) => tx
            .send(bytes)
            .await
            .map_err(|_| JsValue::from_str("input channel closed")),
        None => Err(JsValue::from_str("not connected")),
    }
}

#[wasm_bindgen]
pub fn disconnect() {
    close_current_ws();
    emit_status("disconnected");
}

#[wasm_bindgen]
pub fn is_connected() -> bool {
    CLIENT.with(|cell| cell.borrow().is_connected)
}

#[wasm_bindgen]
pub fn is_connecting() -> bool {
    CLIENT.with(|cell| cell.borrow().is_connecting)
}

fn io_err(e: std::io::Error) -> RusshError {
    RusshError::new(RusshErrorCategory::Io, e.to_string())
}

fn protocol_err(msg: impl Into<String>) -> RusshError {
    RusshError::new(RusshErrorCategory::Protocol, msg.into())
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

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}
type AnyStream = Box<dyn AsyncReadWrite + Unpin>;

enum DirectionalCipher {
    None,
    Aes256Gcm {
        cipher: Box<Aes256GcmCipher>,
        nonce: [u8; 12],
    },
}

impl DirectionalCipher {
    fn new(name: &str, key: &[u8], iv: &[u8]) -> Self {
        if name == "aes256-gcm@openssh.com" {
            if let Ok(cipher) = Aes256GcmCipher::new(key) {
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&iv[..12]);
                return Self::Aes256Gcm {
                    cipher: Box::new(cipher),
                    nonce,
                };
            }
        }
        Self::None
    }

    fn increment_nonce(nonce: &mut [u8; 12]) {
        let mut counter = u64::from_be_bytes(nonce[4..12].try_into().unwrap_or([0; 8]));
        counter = counter.wrapping_add(1);
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    }
}

struct PacketStream<S> {
    inner: S,
    codec: PacketCodec,
    tx_cipher: DirectionalCipher,
    rx_cipher: DirectionalCipher,
}

impl<S: AsyncRead + AsyncWrite + Unpin> PacketStream<S> {
    fn new(stream: S) -> Self {
        Self {
            inner: stream,
            codec: PacketCodec::with_defaults(),
            tx_cipher: DirectionalCipher::None,
            rx_cipher: DirectionalCipher::None,
        }
    }

    fn enable_client_encryption(&mut self, keys: &SessionKeys, neg: &NegotiatedAlgorithms) {
        self.tx_cipher =
            DirectionalCipher::new(&neg.cipher_client_to_server, &keys.key_c2s, &keys.iv_c2s);
        self.rx_cipher =
            DirectionalCipher::new(&neg.cipher_server_to_client, &keys.key_s2c, &keys.iv_s2c);
    }

    async fn read_banner_line(&mut self) -> Result<String, RusshError> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            self.inner.read_exact(&mut byte).await.map_err(io_err)?;
            if byte[0] == b'\n' {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                let s = String::from_utf8(line)
                    .map_err(|_| protocol_err("banner is not valid UTF-8"))?;
                if s.starts_with("SSH-") {
                    return Ok(s);
                }
                line = Vec::new();
            } else {
                if line.len() >= 255 {
                    return Err(protocol_err("banner line too long"));
                }
                line.push(byte[0]);
            }
        }
    }

    async fn write_banner_line(&mut self, banner: &str) -> Result<(), RusshError> {
        let mut bytes = banner.as_bytes().to_vec();
        bytes.extend_from_slice(b"\r\n");
        self.inner.write_all(&bytes).await.map_err(io_err)
    }

    async fn read_packet(&mut self) -> Result<PacketFrame, RusshError> {
        match &mut self.rx_cipher {
            DirectionalCipher::None => {
                let mut len_buf = [0u8; 4];
                self.inner.read_exact(&mut len_buf).await.map_err(io_err)?;
                let pkt_len = u32::from_be_bytes(len_buf) as usize;
                if pkt_len > PacketCodec::DEFAULT_MAX_PACKET_SIZE + 512 {
                    return Err(protocol_err("incoming packet length too large"));
                }
                let mut body = vec![0u8; pkt_len];
                self.inner.read_exact(&mut body).await.map_err(io_err)?;
                let mut full = Vec::with_capacity(4 + pkt_len);
                full.extend_from_slice(&len_buf);
                full.extend_from_slice(&body);
                self.codec.decode(&full)
            }
            DirectionalCipher::Aes256Gcm { cipher, nonce } => {
                let mut len_buf = [0u8; 4];
                self.inner.read_exact(&mut len_buf).await.map_err(io_err)?;
                let pkt_len = u32::from_be_bytes(len_buf) as usize;
                if pkt_len > PacketCodec::DEFAULT_MAX_PACKET_SIZE + 512 {
                    return Err(protocol_err("incoming packet length too large"));
                }
                let mut ct_and_tag = vec![0u8; pkt_len + 16];
                self.inner.read_exact(&mut ct_and_tag).await.map_err(io_err)?;
                let plaintext = cipher
                    .open(nonce, &len_buf, &ct_and_tag)
                    .map_err(|e| RusshError::new(RusshErrorCategory::Crypto, e.to_string()))?;
                DirectionalCipher::increment_nonce(nonce);
                if plaintext.is_empty() {
                    return Err(protocol_err("AES-GCM decrypted to empty plaintext"));
                }
                let padding_len = plaintext[0] as usize;
                let payload_end = plaintext.len().saturating_sub(padding_len);
                if payload_end == 0 {
                    return Err(protocol_err("AES-GCM padding exceeds plaintext length"));
                }
                Ok(PacketFrame::new(plaintext[1..payload_end].to_vec()))
            }
        }
    }

    async fn write_packet(&mut self, frame: &PacketFrame) -> Result<(), RusshError> {
        match &mut self.tx_cipher {
            DirectionalCipher::None => {
                let bytes = self.codec.encode(frame)?;
                self.inner.write_all(&bytes).await.map_err(io_err)
            }
            DirectionalCipher::Aes256Gcm { cipher, nonce } => {
                const BLOCK: usize = 16;
                let payload = &frame.payload;
                let body_len = 1 + payload.len();
                let remainder = body_len % BLOCK;
                let mut padding_len = if remainder == 0 {
                    BLOCK
                } else {
                    BLOCK - remainder
                };
                if padding_len < 4 {
                    padding_len += BLOCK;
                }
                let mut plaintext = Vec::with_capacity(body_len + padding_len);
                plaintext.push(padding_len as u8);
                plaintext.extend_from_slice(payload);
                plaintext.extend(std::iter::repeat_n(0u8, padding_len));
                let packet_length = (plaintext.len() as u32).to_be_bytes();
                let ciphertext_and_tag = cipher
                    .seal(nonce, &packet_length, &plaintext)
                    .map_err(|e| RusshError::new(RusshErrorCategory::Crypto, e.to_string()))?;
                DirectionalCipher::increment_nonce(nonce);
                self.inner.write_all(&packet_length).await.map_err(io_err)?;
                self.inner
                    .write_all(&ciphertext_and_tag)
                    .await
                    .map_err(io_err)
            }
        }
    }
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}
fn channel_data_frame(recipient_channel: u32, data: &[u8]) -> PacketFrame {
    let mut payload = Vec::with_capacity(1 + 4 + 4 + data.len());
    payload.push(94);
    write_u32(&mut payload, recipient_channel);
    write_bytes(&mut payload, data);
    PacketFrame::new(payload)
}

struct BrowserSshClient {
    stream: PacketStream<AnyStream>,
    session: ClientSession,
    channel_manager: ChannelManager,
}

impl BrowserSshClient {
    async fn connect_via_stream(stream: AnyStream, config: ClientConfig) -> Result<Self, RusshError> {
        let mut stream = PacketStream::new(stream);
        stream.write_banner_line(OUR_BANNER).await?;
        let remote_banner = stream.read_banner_line().await?;

        let mut session = ClientSession::new(config);
        session.set_local_version(OUR_BANNER);
        session.handshake(&remote_banner).await?;

        let kexinit_frame = session.send_kexinit()?;
        stream.write_packet(&kexinit_frame).await?;

        let server_kexinit_frame = stream.read_packet().await?;
        let server_kexinit_payload = server_kexinit_frame.payload.clone();
        let server_kexinit_msg = TransportMessage::from_frame(&server_kexinit_frame)?;
        session.store_server_kexinit_payload(server_kexinit_payload)?;
        session.receive_message(server_kexinit_msg)?;

        let ecdh_init_frame = session.send_kex_ecdh_init()?;
        stream.write_packet(&ecdh_init_frame).await?;

        let ecdh_reply_frame = stream.read_packet().await?;
        let ecdh_reply_msg = TransportMessage::from_frame(&ecdh_reply_frame)?;
        let (newkeys_frame, _keys) =
            session.receive_kex_ecdh_reply_and_send_newkeys(&ecdh_reply_msg)?;
        stream.write_packet(&newkeys_frame).await?;

        let _server_newkeys_frame = stream.read_packet().await?;

        if let (Some(keys), Some(neg)) = (session.session_keys(), session.negotiated()) {
            stream.enable_client_encryption(keys, neg);
        }

        let service_frame = session.send_service_request("ssh-userauth")?;
        stream.write_packet(&service_frame).await?;
        let service_accept_msg = loop {
            let frame = stream.read_packet().await?;
            let msg = TransportMessage::from_frame(&frame)?;
            if matches!(msg, TransportMessage::ExtInfo { .. }) {
                session.receive_message(msg)?;
            } else {
                break msg;
            }
        };
        session.receive_message(service_accept_msg)?;

        Ok(Self {
            stream,
            session,
            channel_manager: ChannelManager::new(),
        })
    }

    async fn read_channel_packet(&mut self) -> Result<PacketFrame, RusshError> {
        loop {
            let frame = self.stream.read_packet().await?;
            match frame.payload.first().copied() {
                Some(2) | Some(4) => continue,
                Some(80) => {
                    let want_reply = if frame.payload.len() >= 5 {
                        let nlen = u32::from_be_bytes([
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                            frame.payload[4],
                        ]) as usize;
                        frame.payload.get(5 + nlen).copied().unwrap_or(0) != 0
                    } else {
                        false
                    };
                    if want_reply {
                        self.stream.write_packet(&PacketFrame::new(vec![82])).await?;
                    }
                }
                _ => return Ok(frame),
            }
        }
    }

    async fn authenticate_password(&mut self, password: &str) -> Result<(), RusshError> {
        let user = self.session.config.user.clone();
        let request = UserAuthRequest::Password {
            user,
            service: "ssh-connection".to_owned(),
            password: password.to_owned(),
        };
        let frame = self.session.send_userauth_request(request)?;
        self.stream.write_packet(&frame).await?;
        loop {
            let response_frame = self.stream.read_packet().await?;
            let msg = UserAuthMessage::from_frame(&response_frame)?;
            self.session.receive_userauth_message(msg.clone())?;
            match msg {
                UserAuthMessage::Success => return Ok(()),
                UserAuthMessage::Failure { .. } => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "password authentication rejected",
                    ));
                }
                UserAuthMessage::Banner { .. } => {}
                _ => return Err(protocol_err("unexpected auth response message")),
            }
        }
    }

    async fn authenticate_pubkey(&mut self, signer: &Ed25519Signer) -> Result<(), RusshError> {
        let user = self.session.config.user.clone();
        let session_id = self
            .session
            .session_keys()
            .ok_or_else(|| protocol_err("no session keys for pubkey auth"))?
            .session_id
            .clone();

        let public_key_blob = signer.public_key_blob();
        let signing_payload = build_userauth_signing_payload(
            &session_id,
            &user,
            "ssh-connection",
            "ssh-ed25519",
            &public_key_blob,
        );
        let raw_sig = signer.sign(&signing_payload)?;
        let signature = build_ed25519_signature_blob(
            raw_sig
                .as_slice()
                .try_into()
                .map_err(|_| protocol_err("unexpected signature length"))?,
        );
        let request = UserAuthRequest::PublicKey {
            user,
            service: "ssh-connection".to_owned(),
            algorithm: "ssh-ed25519".to_owned(),
            public_key: public_key_blob,
            signature: Some(signature),
        };
        let frame = self.session.send_userauth_request(request)?;
        self.stream.write_packet(&frame).await?;
        loop {
            let response_frame = self.stream.read_packet().await?;
            let msg = UserAuthMessage::from_frame(&response_frame)?;
            self.session.receive_userauth_message(msg.clone())?;
            match msg {
                UserAuthMessage::Success => return Ok(()),
                UserAuthMessage::Failure { .. } => {
                    return Err(RusshError::new(
                        RusshErrorCategory::Auth,
                        "public key authentication rejected",
                    ));
                }
                UserAuthMessage::Banner { .. } | UserAuthMessage::PublicKeyOk { .. } => {}
                _ => return Err(protocol_err("unexpected auth response message")),
            }
        }
    }

    async fn open_shell(&mut self, term: &str, cols: u32, rows: u32) -> Result<(u32, u32), RusshError> {
        let (local_id, open_msg) = self.channel_manager.open_channel(ChannelKind::Session);
        self.stream.write_packet(&open_msg.to_frame()?).await?;

        let remote_id = loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match &ch {
                ChannelMessage::OpenConfirmation {
                    recipient_channel,
                    sender_channel,
                    ..
                } if *recipient_channel == local_id => {
                    let rid = *sender_channel;
                    self.channel_manager.accept_confirmation(local_id, &ch)?;
                    break rid;
                }
                ChannelMessage::OpenFailure { .. } => return Err(protocol_err("shell channel open rejected")),
                _ => {}
            }
        };

        let pty_req = ChannelMessage::Request {
            recipient_channel: remote_id,
            want_reply: true,
            request: ChannelRequest::PtyReq {
                term: term.to_owned(),
                width_chars: cols,
                height_rows: rows,
                width_pixels: 0,
                height_pixels: 0,
                term_modes: vec![],
            },
        };
        self.stream.write_packet(&pty_req.to_frame()?).await?;
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Success { .. } => break,
                ChannelMessage::Failure { .. } => return Err(protocol_err("pty-req rejected")),
                _ => {}
            }
        }

        let shell_req = ChannelMessage::Request {
            recipient_channel: remote_id,
            want_reply: true,
            request: ChannelRequest::Shell,
        };
        self.stream.write_packet(&shell_req.to_frame()?).await?;
        loop {
            let frame = self.read_channel_packet().await?;
            let ch = ChannelMessage::from_bytes(&frame.payload)?;
            match ch {
                ChannelMessage::Success { .. } => break,
                ChannelMessage::Failure { .. } => {
                    return Err(protocol_err("shell request rejected"));
                }
                _ => {}
            }
        }

        Ok((local_id, remote_id))
    }

    async fn run_shell_session(
        &mut self,
        local_id: u32,
        remote_id: u32,
        input: &mut (impl AsyncRead + Unpin),
        output: &mut (impl AsyncWrite + Unpin),
    ) -> Result<u32, RusshError> {
        let mut buf = vec![0u8; 4096];
        let mut exit_code: u32 = 0;
        let mut input_open = true;
        loop {
            tokio::select! {
                n = input.read(&mut buf), if input_open => {
                    let n = n.map_err(io_err)?;
                    if n == 0 {
                        let eof = ChannelMessage::Eof { recipient_channel: remote_id };
                        self.stream.write_packet(&eof.to_frame()?).await?;
                        input_open = false;
                        continue;
                    }
                    let frame = channel_data_frame(remote_id, &buf[..n]);
                    self.stream.write_packet(&frame).await?;
                }
                frame_res = self.stream.read_packet() => {
                    let frame = frame_res?;
                    let ch = ChannelMessage::from_bytes(&frame.payload)?;
                    let responses = self.channel_manager.process(&ch)?;
                    for response in responses {
                        self.stream.write_packet(&response.to_frame()?).await?;
                    }
                    match ch {
                        ChannelMessage::Data { recipient_channel, data } if recipient_channel == local_id => {
                            output.write_all(&data).await.map_err(io_err)?;
                        }
                        ChannelMessage::ExtendedData { recipient_channel, data, .. } if recipient_channel == local_id => {
                            output.write_all(&data).await.map_err(io_err)?;
                        }
                        ChannelMessage::Request {
                            recipient_channel,
                            request: ChannelRequest::ExitStatus { exit_status },
                            ..
                        } if recipient_channel == local_id => {
                            exit_code = exit_status;
                        }
                        ChannelMessage::Eof { recipient_channel } if recipient_channel == local_id => break,
                        ChannelMessage::Close { recipient_channel } if recipient_channel == local_id => break,
                        _ => {}
                    }
                }
            }
        }
        output.flush().await.map_err(io_err)?;
        Ok(exit_code)
    }
}

struct WsTunnelStream {
    ws: WebSocket,
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl WsTunnelStream {
    fn new(ws: WebSocket, rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            ws,
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl AsyncRead for WsTunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buf.len() {
            let n = std::cmp::min(buf.remaining(), self.buf.len() - self.pos);
            buf.put_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos >= self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.buf = data;
                    self.pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WsTunnelStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.ws.send_with_u8_array(buf) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "websocket send failed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buf.len() {
            let n = std::cmp::min(buf.remaining(), self.buf.len() - self.pos);
            buf.put_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos >= self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.buf = data;
                    self.pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct CallbackWriter;
impl AsyncWrite for CallbackWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        emit_binary(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
