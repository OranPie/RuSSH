//! russh — SSH client binary.
//!
//! Usage:
//!   russh [OPTIONS] [USER@]HOST [COMMAND [ARGS...]]
//!
//! Options:
//!   -p PORT          Remote port (default: 22)
//!   -l USER          Login user
//!   -i IDENTITY      Path to Ed25519 private key (may be repeated; default: ~/.ssh/id_ed25519)
//!   -J JUMP          ProxyJump: [user@]host[:port]
//!   -o KEY=VALUE     OpenSSH-style option (supports StrictHostKeyChecking=no)
//!   -h, --help       Print this help

use std::{
    io::{self, Write},
    path::PathBuf,
    process,
};

use crossterm::terminal;
use russh_crypto::Ed25519Signer;
use russh_net::{SshClient, SshClientConnection};
use russh_observability::{Severity, StderrLogger, VerboseLevel};
use russh_transport::ClientConfig;

fn usage() -> ! {
    eprintln!(
        "Usage: russh [OPTIONS] [USER@]HOST [COMMAND [ARGS...]]\n\
         \n\
         Options:\n\
         \x20 -p PORT          Remote port (default: 22)\n\
         \x20 -l USER          Login user\n\
         \x20 -i IDENTITY      Path to Ed25519 private key (may be repeated)\n\
         \x20 -J JUMP          ProxyJump: [user@]host[:port]\n\
         \x20 -o KEY=VALUE     OpenSSH option (e.g. StrictHostKeyChecking=no)\n\
         \x20 -v               Increase verbosity (-vv, -vvv for more)\n\
         \x20 -q, --quiet      Suppress all diagnostic output\n\
         \x20 -h, --help       Print this help"
    );
    process::exit(1);
}

struct Args {
    host: String,
    port: u16,
    user: String,
    identity: Vec<PathBuf>,
    jump: Option<String>,
    strict_host_key_checking: bool,
    tofu: bool,
    command: Vec<String>,
    verbose: u8,
    quiet: bool,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut host: Option<String> = None;
    let mut port: u16 = 22;
    let mut user: Option<String> = None;
    let mut identity: Vec<PathBuf> = Vec::new();
    let mut jump: Option<String> = None;
    let mut strict = true;
    let mut tofu = true;
    let mut command: Vec<String> = Vec::new();
    let mut verbose: u8 = 0;
    let mut quiet = false;
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
                if let Some(p) = argv.get(i) {
                    identity.push(PathBuf::from(p));
                }
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
                let opt_lower = opt.to_ascii_lowercase();
                if opt_lower.contains("stricthostkeychecking=no") {
                    strict = false;
                    tofu = false;
                }
            }
            "-v" => verbose += 1,
            "-vv" => verbose += 2,
            "-vvv" => verbose += 3,
            "-q" | "--quiet" => quiet = true,
            _ => {}
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
        tofu,
        command,
        verbose,
        quiet,
    }
}

fn resolve_identity(paths: &[PathBuf]) -> Vec<PathBuf> {
    if !paths.is_empty() {
        return paths.to_vec();
    }
    if let Ok(home) = std::env::var("HOME") {
        let default = PathBuf::from(home).join(".ssh").join("id_ed25519");
        if default.exists() {
            return vec![default];
        }
    }
    Vec::new()
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

fn try_load_seed(path: &std::path::Path) -> Option<[u8; 32]> {
    match russh_cli::load_ed25519_seed(path) {
        Ok(seed) => Some(seed),
        Err(e) => {
            eprintln!("russh: warning: cannot load {}: {e}", path.display());
            None
        }
    }
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
    let log_level = VerboseLevel::from_flags(args.verbose, args.quiet);
    let log = StderrLogger::new(log_level, "russh");

    // Initialize tracing subscriber so russh-net log calls emit to stderr.
    let tracing_level = match log_level {
        VerboseLevel::Quiet => tracing::Level::ERROR,
        VerboseLevel::Normal => tracing::Level::WARN,
        VerboseLevel::Verbose => tracing::Level::INFO,
        VerboseLevel::Debug => tracing::Level::DEBUG,
        VerboseLevel::Trace => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_max_level(tracing_level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let identity_paths = resolve_identity(&args.identity);

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

        let jump_seed = identity_paths
            .first()
            .map(|p| load_seed(p))
            .unwrap_or_else(|| {
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

    log.log(
        Severity::Info,
        &format!("connected to {}:{}", args.host, args.port),
    );

    // TOFU / known-hosts check.
    if args.tofu {
        if let Some(key_blob) = conn.server_host_key_blob() {
            russh_cli::verify_or_trust_host_key(&args.host, args.port, key_blob).unwrap_or_else(
                |e| {
                    eprintln!("russh: {e}");
                    process::exit(1);
                },
            );
        }
        log.log(Severity::Debug, "host key verified");
    }

    // Authenticate: try each identity file (pubkey) in order, fall back to password.
    let mut authed = false;
    for id_path in &identity_paths {
        if let Some(seed) = try_load_seed(id_path) {
            let signer = Ed25519Signer::from_seed(&seed);
            match conn.authenticate_pubkey(&signer).await {
                Ok(()) => {
                    authed = true;
                    break;
                }
                _ => continue,
            }
        }
    }

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

    log.log(Severity::Info, "authenticated");

    if args.command.is_empty() {
        // Interactive shell mode.
        log.log(Severity::Debug, "opening interactive shell");
        let (cols, rows) = terminal::size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
        let (local_id, remote_id) = conn
            .open_shell(&term, cols as u32, rows as u32)
            .await
            .unwrap_or_else(|e| {
                eprintln!("russh: shell open failed: {e}");
                process::exit(255);
            });

        terminal::enable_raw_mode().unwrap_or_else(|e| {
            eprintln!("russh: enable raw mode failed: {e}");
            process::exit(1);
        });

        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let exit_code = conn
            .run_shell_session(local_id, remote_id, &mut stdin, &mut stdout)
            .await
            .unwrap_or(0);

        terminal::disable_raw_mode().ok();
        conn.disconnect().await.ok();
        process::exit(exit_code as i32);
    }

    let cmd = args.command.join(" ");
    log.log(Severity::Debug, &format!("exec: {cmd}"));
    let result = conn.exec(&cmd).await.unwrap_or_else(|e| {
        eprintln!("russh: exec failed: {e}");
        process::exit(255);
    });

    io::stdout().write_all(&result.stdout).ok();
    io::stderr().write_all(&result.stderr).ok();
    conn.disconnect().await.ok();
    process::exit(result.exit_code.unwrap_or(0) as i32);
}
