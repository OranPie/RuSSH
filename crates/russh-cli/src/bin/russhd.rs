//! russhd — SSH server binary.
//!
//! Usage:
//!   russhd [OPTIONS]
//!
//! Options:
//!   -p PORT     Listen port (default: 2222)
//!   -b ADDR     Bind address (default: 0.0.0.0)
//!   -k KEY      Path to Ed25519 host key file (generated + saved if absent)
//!   -r ROOT     SFTP/SCP root directory (default: current directory)
//!   --help      Print this help
//!
//! The server executes `exec` requests via `sh -c`.  SFTP and SCP are served
//! from ROOT.  No authentication policy is enforced beyond the RuSSH default
//! (any well-formed public-key handshake is accepted).

use std::{path::PathBuf, process, sync::Arc};

use russh_crypto::{Ed25519Signer, OsRng, RandomSource, Signer};
use russh_net::{SessionHandler, SshServer};
use russh_transport::ServerConfig;

fn usage() -> ! {
    eprintln!(
        "Usage: russhd [OPTIONS]\n\
         \n\
         Options:\n\
         \x20 -p PORT     Listen port (default: 2222)\n\
         \x20 -b ADDR     Bind address (default: 0.0.0.0)\n\
         \x20 -k KEY      Path to host key file (generated + saved if absent)\n\
         \x20 -r ROOT     SFTP/SCP root directory (default: \".\")\n\
         \x20 --help      Print this help"
    );
    process::exit(1);
}

struct CliArgs {
    port: u16,
    bind: String,
    host_key: Option<PathBuf>,
    root: PathBuf,
}

fn parse_args() -> CliArgs {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut port: u16 = 2222;
    let mut bind = "0.0.0.0".to_string();
    let mut host_key: Option<PathBuf> = None;
    let mut root = PathBuf::from(".");

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
            _ => {}
        }
        i += 1;
    }

    CliArgs {
        port,
        bind,
        host_key,
        root,
    }
}

/// Load an existing host key or generate and persist a fresh one.
/// Returns the 32-byte seed to pass to `ServerConfig`.
fn resolve_host_key(path: Option<&PathBuf>) -> Option<[u8; 32]> {
    match path {
        None => None, // let transport generate an ephemeral key every run
        Some(p) if p.exists() => {
            let seed = russh_cli::load_ed25519_seed(p).unwrap_or_else(|e| {
                eprintln!("russhd: failed to load host key {}: {e}", p.display());
                process::exit(1);
            });
            Some(seed)
        }
        Some(p) => {
            // Generate a fresh seed and persist it.
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

fn hex_fingerprint(key_blob: &[u8]) -> String {
    use std::fmt::Write;
    // Compute SHA-256 fingerprint as "SHA256:<base64>" (like ssh-keygen -l).
    // We use a simple hex representation here to avoid pulling in sha2 directly.
    let mut s = String::new();
    for b in key_blob.iter().take(8) {
        let _ = write!(s, "{b:02x}");
    }
    s.push_str("..");
    s
}

/// [`SessionHandler`] that executes commands via `sh -c` and serves
/// SFTP/SCP from a configured root directory.
#[derive(Clone)]
struct ShellSessionHandler {
    sftp_root: PathBuf,
}

impl SessionHandler for ShellSessionHandler {
    fn exec(&self, cmd: &str) -> Vec<u8> {
        match std::process::Command::new("sh").arg("-c").arg(cmd).output() {
            Ok(out) => {
                // Return stdout; stderr is visible on the server console.
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
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let seed = resolve_host_key(args.host_key.as_ref());

    let mut cfg = ServerConfig::secure_defaults();
    cfg.host_key_seed = seed;

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
