//! russhd — SSH server binary.
//!
//! Usage:
//!   russhd [OPTIONS]
//!
//! Options:
//!   -p PORT       Listen port (default: 2222)
//!   -b ADDR       Bind address (default: 0.0.0.0)
//!   -k KEY        Path to Ed25519 host key file (generated + saved if absent)
//!   -r ROOT       SFTP/SCP root directory (default: current directory)
//!   -A AUTHKEYS   Path to authorized_keys file (default: ~/.ssh/authorized_keys)
//!   --help        Print this help
//!
//! The server executes `exec` requests via `sh -c` and supports interactive
//! shell sessions.  Only keys listed in the authorized_keys file are accepted.

use std::{path::PathBuf, process, sync::Arc};

use russh_auth::{AuthMethod, MemoryAuthorizedKeys, ServerAuthPolicy};
use russh_crypto::{Ed25519Signer, OsRng, RandomSource, Signer};
use russh_net::{SessionHandler, SshServer};
use russh_transport::ServerConfig;

fn usage() -> ! {
    eprintln!(
        "Usage: russhd [OPTIONS]\n\
         \n\
         Options:\n\
         \x20 -p PORT       Listen port (default: 2222)\n\
         \x20 -b ADDR       Bind address (default: 0.0.0.0)\n\
         \x20 -k KEY        Path to host key file (generated + saved if absent)\n\
         \x20 -r ROOT       SFTP/SCP root directory (default: \".\")\n\
         \x20 -A AUTHKEYS   Path to authorized_keys file\n\
         \x20 --help        Print this help"
    );
    process::exit(1);
}

struct CliArgs {
    port: u16,
    bind: String,
    host_key: Option<PathBuf>,
    root: PathBuf,
    authorized_keys: Option<PathBuf>,
}

fn parse_args() -> CliArgs {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut port: u16 = 2222;
    let mut bind = "0.0.0.0".to_string();
    let mut host_key: Option<PathBuf> = None;
    let mut root = PathBuf::from(".");
    let mut authorized_keys: Option<PathBuf> = None;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--help" => usage(),
            "-p" => {
                i += 1;
                port = argv.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                    eprintln!("error: -p requires a port number");
                    process::exit(1);
                });
            }
            "-b" => {
                i += 1;
                bind = argv.get(i).cloned().unwrap_or(bind);
            }
            "-k" => {
                i += 1;
                host_key = argv.get(i).map(PathBuf::from);
            }
            "-r" => {
                i += 1;
                root = argv.get(i).map(PathBuf::from).unwrap_or(root);
            }
            "-A" => {
                i += 1;
                authorized_keys = argv.get(i).map(PathBuf::from);
            }
            _ => {}
        }
        i += 1;
    }

    CliArgs {
        port,
        bind,
        host_key,
        root,
        authorized_keys,
    }
}

/// Load an existing host key or generate and persist a fresh one.
fn resolve_host_key(path: Option<&PathBuf>) -> Option<[u8; 32]> {
    match path {
        None => None,
        Some(p) if p.exists() => {
            let seed = russh_cli::load_ed25519_seed(p).unwrap_or_else(|e| {
                eprintln!("russhd: failed to load host key {}: {e}", p.display());
                process::exit(1);
            });
            Some(seed)
        }
        Some(p) => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            russh_cli::save_seed_file(p, &seed).unwrap_or_else(|e| {
                eprintln!("russhd: warning: could not save host key: {e}");
            });
            let signer = Ed25519Signer::from_seed(&seed);
            eprintln!(
                "russhd: generated host key saved to {} (fingerprint: {})",
                p.display(),
                hex_fingerprint(&signer.public_key_blob())
            );
            Some(seed)
        }
    }
}

/// Load authorized_keys from a file.  Falls back to ~/.ssh/authorized_keys.
fn load_authorized_keys(path: Option<&PathBuf>) -> Option<MemoryAuthorizedKeys> {
    let resolved = path.cloned().or_else(|| {
        let home = std::env::var("HOME").ok()?;
        let p = PathBuf::from(home).join(".ssh").join("authorized_keys");
        if p.exists() { Some(p) } else { None }
    })?;

    let content = std::fs::read_to_string(&resolved).unwrap_or_else(|e| {
        eprintln!(
            "russhd: warning: cannot read authorized_keys {}: {e}",
            resolved.display()
        );
        String::new()
    });

    if content.is_empty() {
        return None;
    }

    let mut store = MemoryAuthorizedKeys::new();
    match store.load_authorized_keys("*", &content) {
        Ok(n) => eprintln!(
            "russhd: loaded {n} authorized key(s) from {}",
            resolved.display()
        ),
        Err(e) => eprintln!("russhd: warning: authorized_keys parse error: {e}"),
    }
    Some(store)
}

fn hex_fingerprint(key_blob: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for b in key_blob.iter().take(8) {
        let _ = write!(s, "{b:02x}");
    }
    s.push_str("..");
    s
}

/// [`SessionHandler`] that executes commands via `sh -c`, supports interactive
/// shell sessions, and serves SFTP/SCP from a configured root directory.
#[derive(Clone)]
struct ShellSessionHandler {
    sftp_root: PathBuf,
}

impl SessionHandler for ShellSessionHandler {
    fn exec(&self, cmd: &str) -> Vec<u8> {
        match std::process::Command::new("sh").arg("-c").arg(cmd).output() {
            Ok(out) => {
                let _ = std::io::Write::write_all(&mut std::io::stderr(), &out.stderr);
                out.stdout
            }
            Err(e) => format!("russhd: exec error: {e}\n").into_bytes(),
        }
    }

    fn sftp_root(&self) -> Option<PathBuf> {
        Some(self.sftp_root.clone())
    }

    fn scp_root(&self) -> Option<PathBuf> {
        Some(self.sftp_root.clone())
    }

    fn shell_command(&self) -> Option<String> {
        Some(std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()))
    }
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let seed = resolve_host_key(args.host_key.as_ref());
    let auth_keys = load_authorized_keys(args.authorized_keys.as_ref());

    let mut cfg = ServerConfig::secure_defaults();
    cfg.host_key_seed = seed;

    // Build auth policy: pubkey-only when authorized_keys is present.
    if let Some(keys) = auth_keys {
        let mut policy = ServerAuthPolicy::secure_defaults();
        policy
            .set_allowed_methods([AuthMethod::PublicKey])
            .unwrap_or_else(|e| {
                eprintln!("russhd: auth policy error: {e}");
                process::exit(1);
            });
        policy.set_authorized_keys(keys);
        cfg.auth_policy = Some(policy);
    }

    let addr = format!("{}:{}", args.bind, args.port);
    let server = SshServer::bind(&addr, cfg).await.unwrap_or_else(|e| {
        eprintln!("russhd: bind {addr} failed: {e}");
        process::exit(1);
    });

    let actual = server
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or(addr.clone());
    eprintln!("russhd: listening on {actual}");
    eprintln!("russhd: SFTP/SCP root: {}", args.root.display());

    let root: Arc<PathBuf> = Arc::new(args.root);

    loop {
        match server.accept().await {
            Ok(conn) => {
                let handler = ShellSessionHandler {
                    sftp_root: (*root).clone(),
                };
                tokio::spawn(async move {
                    if let Err(e) = conn.run(handler).await {
                        eprintln!("russhd: session error: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("russhd: accept error: {e}");
            }
        }
    }
}
