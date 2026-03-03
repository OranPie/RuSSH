//! russh — SSH client binary.
//!
//! Usage:
//!   russh [OPTIONS] [USER@]HOST COMMAND [ARGS...]
//!
//! Options:
//!   -p PORT          Remote port (default: 22)
//!   -l USER          Login user
//!   -i IDENTITY      Path to Ed25519 private key (default: ~/.ssh/id_ed25519)
//!   -J JUMP          ProxyJump: [user@]host[:port]
//!   -o KEY=VALUE     OpenSSH-style option (supports StrictHostKeyChecking=no)
//!   -h, --help       Print this help

use std::{
    io::{self, Write},
    path::PathBuf,
    process,
};

use russh_crypto::Ed25519Signer;
use russh_net::{SshClient, SshClientConnection};
use russh_transport::ClientConfig;

fn usage() -> ! {
    eprintln!(
        "Usage: russh [OPTIONS] [USER@]HOST COMMAND [ARGS...]\n\
         \n\
         Options:\n\
         \x20 -p PORT          Remote port (default: 22)\n\
         \x20 -l USER          Login user\n\
         \x20 -i IDENTITY      Path to Ed25519 private key (default: ~/.ssh/id_ed25519)\n\
         \x20 -J JUMP          ProxyJump: [user@]host[:port]\n\
         \x20 -o KEY=VALUE     OpenSSH option (e.g. StrictHostKeyChecking=no)\n\
         \x20 -h, --help       Print this help"
    );
    process::exit(1);
}

struct Args {
    host: String,
    port: u16,
    user: String,
    identity: Option<PathBuf>,
    jump: Option<String>,
    strict_host_key_checking: bool,
    command: Vec<String>,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut host: Option<String> = None;
    let mut port: u16 = 22;
    let mut user: Option<String> = None;
    let mut identity: Option<PathBuf> = None;
    let mut jump: Option<String> = None;
    let mut strict = true;
    let mut command: Vec<String> = Vec::new();
    let mut collecting_cmd = false;

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if collecting_cmd || (!arg.starts_with('-') && host.is_some()) {
            command.push(arg.clone());
            collecting_cmd = true;
            i += 1;
            continue;
        }
        if !arg.starts_with('-') {
            host = Some(arg.clone());
            i += 1;
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" => usage(),
            "--" => {
                collecting_cmd = true;
                i += 1;
            }
            "-p" => {
                i += 1;
                port = argv.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                    eprintln!("error: -p requires a port number");
                    process::exit(1);
                });
            }
            "-l" => {
                i += 1;
                user = argv.get(i).cloned();
            }
            "-i" => {
                i += 1;
                identity = argv.get(i).map(PathBuf::from);
            }
            "-J" => {
                i += 1;
                jump = argv.get(i).cloned();
            }
            s if s.starts_with("-o") => {
                let opt = if s.len() > 2 {
                    s[2..].trim().to_string()
                } else {
                    i += 1;
                    argv.get(i).cloned().unwrap_or_default()
                };
                if opt
                    .to_ascii_lowercase()
                    .contains("stricthostkeychecking=no")
                {
                    strict = false;
                }
            }
            _ => {} // ignore unknown options for compatibility
        }
        i += 1;
    }

    let raw_host = host.unwrap_or_else(|| usage());

    let (parsed_user, parsed_host) = if let Some((u, h)) = raw_host.split_once('@') {
        (u.to_string(), h.to_string())
    } else {
        (
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "root".into()),
            raw_host,
        )
    };

    Args {
        host: parsed_host,
        port,
        user: user.unwrap_or(parsed_user),
        identity,
        jump,
        strict_host_key_checking: strict,
        command,
    }
}

fn resolve_identity(path: Option<&PathBuf>) -> Option<PathBuf> {
    if let Some(p) = path {
        return Some(p.clone());
    }
    let home = std::env::var("HOME").ok()?;
    let default = PathBuf::from(home).join(".ssh").join("id_ed25519");
    if default.exists() {
        Some(default)
    } else {
        None
    }
}

fn read_password(prompt: &str) -> String {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).ok();
    buf.trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string()
}

fn load_seed(path: &std::path::Path) -> [u8; 32] {
    russh_cli::load_ed25519_seed(path).unwrap_or_else(|e| {
        eprintln!("russh: {e}");
        process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let identity_path = resolve_identity(args.identity.as_ref());

    let mut cfg = ClientConfig::secure_defaults(&args.user);
    cfg.strict_host_key_checking = args.strict_host_key_checking;

    // Connect (optionally via ProxyJump).
    let mut conn: SshClientConnection = if let Some(jump_str) = &args.jump {
        let (jump_user, jump_hostport) = if let Some((u, h)) = jump_str.split_once('@') {
            (u.to_string(), h.to_string())
        } else {
            (args.user.clone(), jump_str.clone())
        };
        let (jump_host, jump_port) = if let Some((h, p)) = jump_hostport.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(22))
        } else {
            (jump_hostport, 22u16)
        };

        let mut jump_cfg = ClientConfig::secure_defaults(&jump_user);
        jump_cfg.strict_host_key_checking = args.strict_host_key_checking;

        let jump_seed = identity_path.as_deref().map(load_seed).unwrap_or_else(|| {
            eprintln!("russh: -J requires an identity file (-i)");
            process::exit(1);
        });

        SshClient::connect_via_jump(
            format!("{jump_host}:{jump_port}"),
            jump_cfg,
            move |jconn| {
                let s = Ed25519Signer::from_seed(&jump_seed);
                Box::pin(async move { jconn.authenticate_pubkey(&s).await })
            },
            &args.host,
            args.port,
            cfg,
        )
        .await
        .unwrap_or_else(|e| {
            eprintln!("russh: connect via jump failed: {e}");
            process::exit(255);
        })
    } else {
        SshClientConnection::connect(format!("{}:{}", args.host, args.port), cfg)
            .await
            .unwrap_or_else(|e| {
                eprintln!("russh: connect failed: {e}");
                process::exit(255);
            })
    };

    // Authenticate: try pubkey first, fall back to password.
    let authed = if let Some(ref p) = identity_path {
        let seed = load_seed(p);
        let signer = Ed25519Signer::from_seed(&seed);
        conn.authenticate_pubkey(&signer).await.is_ok()
    } else {
        false
    };

    if !authed {
        let prompt = format!("{}@{}'s password: ", args.user, args.host);
        let password = read_password(&prompt);
        conn.authenticate_password(&password)
            .await
            .unwrap_or_else(|e| {
                eprintln!("russh: authentication failed: {e}");
                process::exit(1);
            });
    }

    if args.command.is_empty() {
        eprintln!("russh: interactive shell not supported — provide a command to execute");
        conn.disconnect().await.ok();
        process::exit(1);
    }

    let cmd = args.command.join(" ");
    let result = conn.exec(&cmd).await.unwrap_or_else(|e| {
        eprintln!("russh: exec failed: {e}");
        process::exit(255);
    });

    io::stdout().write_all(&result.stdout).ok();
    io::stderr().write_all(&result.stderr).ok();
    conn.disconnect().await.ok();
    process::exit(result.exit_code.unwrap_or(0) as i32);
}
