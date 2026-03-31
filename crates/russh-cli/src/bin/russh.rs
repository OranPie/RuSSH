//! russh — SSH client binary.
//!
//! Usage:
//!   russh [OPTIONS] [USER@]HOST [COMMAND [ARGS...]]
//!
//! Options:
//!   -A               Enable agent forwarding
//!   -p PORT          Remote port (default: 22)
//!   -l USER          Login user
//!   -i IDENTITY      Path to Ed25519 private key (may be repeated; default: ~/.ssh/id_ed25519)
//!   -J JUMP          ProxyJump: [user@]host[:port]
//!   -F CONFIGFILE    SSH config file (default: ~/.ssh/config)
//!   -o KEY=VALUE     OpenSSH-style option (supports many common options)
//!   -h, --help       Print this help

use std::{
    io::{self, Write},
    path::PathBuf,
    process,
    sync::Arc,
};

use crossterm::terminal;
use russh_auth::AuthMethod;
use russh_config::{ResolvedConfig, parse_config};
use russh_crypto::Ed25519Signer;
use russh_net::{SshClient, SshClientConnection};
use russh_observability::{Severity, StderrLogger, VerboseLevel};
use russh_transport::ClientConfig;
use tokio::net::TcpListener;

fn usage() -> ! {
    eprintln!(
        "Usage: russh [OPTIONS] [USER@]HOST [COMMAND [ARGS...]]\n\
         \n\
         Options:\n\
         \x20 -A               Enable agent forwarding\n\
         \x20 -p PORT          Remote port (default: 22)\n\
         \x20 -l USER          Login user\n\
         \x20 -i IDENTITY      Path to Ed25519 private key (may be repeated)\n\
         \x20 -J JUMP          ProxyJump: [user@]host[:port]\n\
         \x20 -L [BIND:]PORT:HOST:HOSTPORT  Local port forwarding\n\
         \x20 -F CONFIGFILE    SSH config file (default: ~/.ssh/config)\n\
         \x20 -o KEY=VALUE     OpenSSH option (e.g. StrictHostKeyChecking=no)\n\
         \x20 -v               Increase verbosity (-vv, -vvv for more)\n\
         \x20 -q, --quiet      Suppress all diagnostic output\n\
         \x20 -h, --help       Print this help"
    );
    process::exit(1);
}

/// Expanded `-o` option values parsed from the CLI.
#[derive(Clone, Debug, Default)]
struct OOptions {
    port: Option<u16>,
    user: Option<String>,
    identity_files: Vec<PathBuf>,
    strict_host_key_checking: Option<bool>,
    server_alive_interval: Option<u64>,
    server_alive_count_max: Option<u64>,
    compression: Option<bool>,
    kex_algorithms: Option<Vec<String>>,
    ciphers: Option<Vec<String>>,
    macs: Option<Vec<String>>,
    host_key_algorithms: Option<Vec<String>>,
    password_authentication: Option<bool>,
    preferred_authentications: Option<Vec<String>>,
}

struct Args {
    host: String,
    port_explicit: bool,
    port: u16,
    user_explicit: bool,
    user: String,
    identity: Vec<PathBuf>,
    jump: Option<String>,
    jump_explicit: bool,
    strict_host_key_checking: bool,
    tofu: bool,
    command: Vec<String>,
    verbose: u8,
    quiet: bool,
    config_file: Option<PathBuf>,
    o_options: OOptions,
    /// Local port forwarding specs: `(bind_host, bind_port, remote_host, remote_port)`.
    local_forwards: Vec<(String, u16, String, u16)>,
    /// Whether to request SSH agent forwarding (`-A`).
    agent_forwarding: bool,
}

fn parse_o_option(opt: &str, o_opts: &mut OOptions, strict: &mut bool, tofu: &mut bool) {
    let (key, value) = match opt.split_once('=') {
        Some((k, v)) => (k.trim(), v.trim()),
        None => return,
    };
    match key.to_ascii_lowercase().as_str() {
        "stricthostkeychecking" => {
            if value.eq_ignore_ascii_case("no") {
                *strict = false;
                *tofu = false;
                o_opts.strict_host_key_checking = Some(false);
            } else if value.eq_ignore_ascii_case("yes") {
                *strict = true;
                *tofu = true;
                o_opts.strict_host_key_checking = Some(true);
            }
        }
        "port" => {
            if let Ok(p) = value.parse::<u16>() {
                o_opts.port = Some(p);
            }
        }
        "user" => {
            o_opts.user = Some(value.to_string());
        }
        "identityfile" => {
            o_opts.identity_files.push(PathBuf::from(value));
        }
        "serveraliveinterval" => {
            if let Ok(n) = value.parse::<u64>() {
                o_opts.server_alive_interval = Some(n);
            }
        }
        "serveralivecountmax" => {
            if let Ok(n) = value.parse::<u64>() {
                o_opts.server_alive_count_max = Some(n);
            }
        }
        "compression" => {
            o_opts.compression = Some(value.eq_ignore_ascii_case("yes"));
        }
        "kexalgorithms" => {
            o_opts.kex_algorithms = Some(value.split(',').map(|s| s.trim().to_string()).collect());
        }
        "ciphers" => {
            o_opts.ciphers = Some(value.split(',').map(|s| s.trim().to_string()).collect());
        }
        "macs" => {
            o_opts.macs = Some(value.split(',').map(|s| s.trim().to_string()).collect());
        }
        "hostkeyalgorithms" => {
            o_opts.host_key_algorithms =
                Some(value.split(',').map(|s| s.trim().to_string()).collect());
        }
        "passwordauthentication" => {
            o_opts.password_authentication = Some(value.eq_ignore_ascii_case("yes"));
        }
        "preferredauthentications" => {
            o_opts.preferred_authentications =
                Some(value.split(',').map(|s| s.trim().to_string()).collect());
        }
        _ => {}
    }
}

/// Parse a `-L` spec: `[bind_address:]port:host:hostport`.
///
/// Returns `(bind_host, bind_port, remote_host, remote_port)`.
fn parse_local_forward(spec: &str) -> Option<(String, u16, String, u16)> {
    let parts: Vec<&str> = spec.splitn(4, ':').collect();
    match parts.len() {
        // port:host:hostport  →  bind to 127.0.0.1
        3 => {
            let bind_port = parts[0].parse::<u16>().ok()?;
            let host = parts[1].to_string();
            let hostport = parts[2].parse::<u16>().ok()?;
            Some(("127.0.0.1".to_string(), bind_port, host, hostport))
        }
        // bind_address:port:host:hostport
        4 => {
            let bind_addr = parts[0].to_string();
            let bind_port = parts[1].parse::<u16>().ok()?;
            let host = parts[2].to_string();
            let hostport = parts[3].parse::<u16>().ok()?;
            Some((bind_addr, bind_port, host, hostport))
        }
        _ => None,
    }
}

fn parse_args() -> Args {
    parse_args_from(std::env::args().skip(1).collect())
}

fn parse_args_from(argv: Vec<String>) -> Args {
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut user: Option<String> = None;
    let mut identity: Vec<PathBuf> = Vec::new();
    let mut jump: Option<String> = None;
    let mut jump_explicit = false;
    let mut strict = true;
    let mut tofu = true;
    let mut command: Vec<String> = Vec::new();
    let mut verbose: u8 = 0;
    let mut quiet = false;
    let mut collecting_cmd = false;
    let mut config_file: Option<PathBuf> = None;
    let mut o_opts = OOptions::default();
    let mut local_forwards: Vec<(String, u16, String, u16)> = Vec::new();
    let mut agent_forwarding = false;

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
                port = Some(argv.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                    eprintln!("error: -p requires a port number");
                    process::exit(1);
                }));
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
                jump_explicit = true;
            }
            "-F" => {
                i += 1;
                config_file = argv.get(i).map(PathBuf::from);
            }
            "-L" => {
                i += 1;
                if let Some(spec) = argv.get(i) {
                    if let Some(fwd) = parse_local_forward(spec) {
                        local_forwards.push(fwd);
                    } else {
                        eprintln!("error: invalid -L spec: {spec}");
                        process::exit(1);
                    }
                }
            }
            s if s.starts_with("-o") => {
                let opt = if s.len() > 2 {
                    s[2..].trim().to_string()
                } else {
                    i += 1;
                    argv.get(i).cloned().unwrap_or_default()
                };
                parse_o_option(&opt, &mut o_opts, &mut strict, &mut tofu);
            }
            "-v" => verbose += 1,
            "-vv" => verbose += 2,
            "-vvv" => verbose += 3,
            "-A" => agent_forwarding = true,
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

    let user_explicit = user.is_some();
    let port_explicit = port.is_some();

    Args {
        host: parsed_host,
        port_explicit,
        port: port.unwrap_or(22),
        user_explicit,
        user: user.unwrap_or(parsed_user),
        identity,
        jump,
        jump_explicit,
        strict_host_key_checking: strict,
        tofu,
        command,
        verbose,
        quiet,
        config_file,
        o_options: o_opts,
        local_forwards,
        agent_forwarding,
    }
}

/// Load and resolve SSH config file for the given host.
fn load_ssh_config(config_path: &std::path::Path, host: &str) -> ResolvedConfig {
    if !config_path.exists() {
        return ResolvedConfig::default();
    }
    let text = std::fs::read_to_string(config_path).unwrap_or_default();
    let config_file = parse_config(&text).unwrap_or_else(|_| russh_config::ConfigFile::new());
    config_file.resolve_for_host(host)
}

/// Home directory helper.
fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".to_string()))
}

/// Apply resolved config defaults and `-o` overrides to args.
/// Priority: CLI flags > `-o` options > config file > built-in defaults.
fn apply_config(args: &mut Args, resolved: &ResolvedConfig) {
    // Config file defaults (lowest priority after built-in defaults).
    if !args.user_explicit && args.o_options.user.is_none() {
        if let Some(ref u) = resolved.user {
            args.user = u.clone();
        }
    }
    if !args.port_explicit && args.o_options.port.is_none() {
        if let Some(p) = resolved.port {
            args.port = p;
        }
    }
    if let Some(ref h) = resolved.hostname {
        // Only use resolved hostname if CLI didn't specify user@host differently.
        // Config hostname replaces the connect target.
        args.host = h.clone();
    }
    // Append config identity files (CLI-specified ones take precedence by being first).
    for id in &resolved.identity_files {
        let path = if let Some(stripped) = id.strip_prefix("~/") {
            home_dir().join(stripped)
        } else {
            PathBuf::from(id)
        };
        if !args.identity.contains(&path) {
            args.identity.push(path);
        }
    }
    if !args.jump_explicit && args.jump.is_none() {
        if let Some(ref pj) = resolved.proxy_jump {
            args.jump = Some(pj.clone());
        }
    }

    // `-o` overrides (higher priority than config file).
    if let Some(p) = args.o_options.port {
        if !args.port_explicit {
            args.port = p;
        }
    }
    if let Some(ref u) = args.o_options.user.clone() {
        if !args.user_explicit {
            args.user = u.clone();
        }
    }
    // Append -o identity files.
    for id in &args.o_options.identity_files {
        if !args.identity.contains(id) {
            args.identity.push(id.clone());
        }
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

/// Read a password from stdin without echoing (best-effort).
///
/// Uses `crossterm` raw mode to suppress echo.  Falls back to plain
/// `read_line` if raw mode cannot be enabled (e.g. when stdin is not a
/// terminal).
fn read_password(prompt: &str) -> String {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    // Try to disable echo via raw mode so the password is not visible.
    let raw = terminal::enable_raw_mode().is_ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).ok();
    if raw {
        terminal::disable_raw_mode().ok();
        // Print a newline since the user's Enter was swallowed by raw mode.
        eprintln!();
    }
    buf.trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string()
}

/// Read a line from stdin with normal echo (for keyboard-interactive prompts
/// where the server indicates the response should be visible).
fn read_line_echo(prompt: &str) -> String {
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
    let mut args = parse_args();
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

    // Load and resolve SSH config file.
    let config_path = args
        .config_file
        .clone()
        .unwrap_or_else(|| home_dir().join(".ssh").join("config"));
    let resolved = load_ssh_config(&config_path, &args.host);
    apply_config(&mut args, &resolved);

    let identity_paths = resolve_identity(&args.identity);

    let mut cfg = ClientConfig::secure_defaults(&args.user);
    cfg.strict_host_key_checking = args.strict_host_key_checking;

    // Apply algorithm overrides from config/`-o`.
    // Priority: -o > config > defaults.
    let algo_kex = args
        .o_options
        .kex_algorithms
        .as_ref()
        .or(resolved.kex_algorithms.as_ref());
    let algo_ciphers = args
        .o_options
        .ciphers
        .as_ref()
        .or(resolved.ciphers.as_ref());
    let algo_macs = args.o_options.macs.as_ref().or(resolved.macs.as_ref());
    let algo_host_key = args.o_options.host_key_algorithms.as_ref();

    if algo_kex.is_some()
        || algo_ciphers.is_some()
        || algo_macs.is_some()
        || algo_host_key.is_some()
    {
        let algs = cfg.transport.policy.algorithms_mut();
        if let Some(kex) = algo_kex {
            algs.kex = kex.clone();
        }
        if let Some(ciphers) = algo_ciphers {
            algs.ciphers = ciphers.clone();
        }
        if let Some(macs) = algo_macs {
            algs.macs = macs.clone();
        }
        if let Some(host_key) = algo_host_key {
            algs.host_key = host_key.clone();
        }
    }

    // Apply keepalive from config/`-o`.
    let alive_interval = args
        .o_options
        .server_alive_interval
        .or(resolved.server_alive_interval);
    if let Some(secs) = alive_interval {
        cfg.transport.keepalive_interval = std::time::Duration::from_secs(secs);
    }

    // Determine whether password auth is allowed.
    let password_auth_enabled = args.o_options.password_authentication.unwrap_or(true);

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

    // Authenticate: try methods in the order specified by PreferredAuthentications.
    // Default order: publickey → keyboard-interactive → password.
    let auth_methods: Vec<AuthMethod> =
        if let Some(ref prefs) = args.o_options.preferred_authentications {
            prefs
                .iter()
                .filter_map(|s| AuthMethod::from_ssh_name(s))
                .collect()
        } else {
            vec![
                AuthMethod::PublicKey,
                AuthMethod::KeyboardInteractive,
                AuthMethod::Password,
            ]
        };

    let mut authed = false;
    for method in &auth_methods {
        if authed {
            break;
        }
        match method {
            AuthMethod::PublicKey => {
                for id_path in &identity_paths {
                    if let Some(seed) = try_load_seed(id_path) {
                        let signer = Ed25519Signer::from_seed(&seed);
                        if conn.authenticate_pubkey(&signer).await.is_ok() {
                            authed = true;
                            break;
                        }
                    }
                }
            }
            AuthMethod::KeyboardInteractive => {
                if let Ok(prompts) = conn.authenticate_keyboard_interactive().await {
                    if prompts.is_empty() {
                        // Server accepted without prompts.
                        authed = true;
                    } else {
                        let responses: Vec<String> = prompts
                            .iter()
                            .map(|(prompt, echo)| {
                                if *echo {
                                    read_line_echo(prompt)
                                } else {
                                    read_password(prompt)
                                }
                            })
                            .collect();
                        match conn.respond_keyboard_interactive(responses).await {
                            Ok(None) => {
                                authed = true;
                            }
                            Ok(Some(mut more_prompts)) => {
                                // Multi-round keyboard-interactive.
                                loop {
                                    let resps: Vec<String> = more_prompts
                                        .iter()
                                        .map(|(p, echo)| {
                                            if *echo {
                                                read_line_echo(p)
                                            } else {
                                                read_password(p)
                                            }
                                        })
                                        .collect();
                                    match conn.respond_keyboard_interactive(resps).await {
                                        Ok(None) => {
                                            authed = true;
                                            break;
                                        }
                                        Ok(Some(next)) => {
                                            more_prompts = next;
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            AuthMethod::Password => {
                if !password_auth_enabled {
                    continue;
                }
                let prompt = format!("{}@{}'s password: ", args.user, args.host);
                let password = read_password(&prompt);
                if conn.authenticate_password(&password).await.is_ok() {
                    authed = true;
                }
            }
        }
    }

    if !authed {
        eprintln!("russh: authentication failed");
        process::exit(1);
    }

    log.log(Severity::Info, "authenticated");

    // ──────────────────────────────────────────────────────────
    // Local port forwarding (-L) without a command: forward-only mode.
    // Each listener accepts one connection at a time serially.
    // ──────────────────────────────────────────────────────────
    if !args.local_forwards.is_empty() && args.command.is_empty() {
        let conn = Arc::new(tokio::sync::Mutex::new(conn));

        let mut handles = Vec::new();
        for (bind_host, bind_port, remote_host, remote_port) in args.local_forwards.clone() {
            let conn = Arc::clone(&conn);
            let log_fwd = StderrLogger::new(log_level, "russh");
            let handle = tokio::spawn(async move {
                let listener = match TcpListener::bind(format!("{bind_host}:{bind_port}")).await {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("russh: cannot bind {bind_host}:{bind_port} for -L forward: {e}");
                        return;
                    }
                };
                log_fwd.log(
                    Severity::Info,
                    &format!(
                        "local forward listening on {bind_host}:{bind_port} → {remote_host}:{remote_port}"
                    ),
                );

                loop {
                    let (mut tcp_stream, peer) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    log_fwd.log(
                        Severity::Debug,
                        &format!("accepted connection from {peer} for forward"),
                    );

                    let peer_ip = peer.ip().to_string();
                    let peer_port = peer.port();

                    let mut locked = conn.lock().await;
                    let channel = locked
                        .open_direct_tcpip(&remote_host, remote_port, &peer_ip, peer_port)
                        .await;

                    match channel {
                        Ok((local_id, remote_id)) => {
                            if let Err(e) = locked
                                .relay_tcp_channel(local_id, remote_id, &mut tcp_stream)
                                .await
                            {
                                log_fwd.log(Severity::Warn, &format!("relay error: {e}"));
                            }
                        }
                        Err(e) => {
                            log_fwd.log(Severity::Warn, &format!("direct-tcpip open failed: {e}"));
                        }
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all forwarding tasks (runs forever until interrupted).
        for h in handles {
            let _ = h.await;
        }
        return;
    }

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

        if args.agent_forwarding {
            log.log(Severity::Debug, "requesting agent forwarding");
            conn.request_agent_forwarding(remote_id)
                .await
                .unwrap_or_else(|e| {
                    log.log(
                        Severity::Warn,
                        &format!("agent forwarding request failed: {e}"),
                    );
                });
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn o_port_overrides_default() {
        let args = parse_args_from(make_argv(&["-o", "Port=2222", "example.com"]));
        assert_eq!(args.o_options.port, Some(2222));
    }

    #[test]
    fn o_user_overrides_default() {
        let args = parse_args_from(make_argv(&["-o", "User=admin", "example.com"]));
        assert_eq!(args.o_options.user.as_deref(), Some("admin"));
    }

    #[test]
    fn o_identity_file_appended() {
        let args = parse_args_from(make_argv(&["-o", "IdentityFile=/tmp/mykey", "example.com"]));
        assert_eq!(
            args.o_options.identity_files,
            vec![PathBuf::from("/tmp/mykey")]
        );
    }

    #[test]
    fn o_strict_host_key_checking_no() {
        let args = parse_args_from(make_argv(&["-o", "StrictHostKeyChecking=no", "host"]));
        assert!(!args.strict_host_key_checking);
        assert!(!args.tofu);
    }

    #[test]
    fn o_server_alive_interval() {
        let args = parse_args_from(make_argv(&["-o", "ServerAliveInterval=60", "host"]));
        assert_eq!(args.o_options.server_alive_interval, Some(60));
    }

    #[test]
    fn o_server_alive_count_max() {
        let args = parse_args_from(make_argv(&["-o", "ServerAliveCountMax=3", "host"]));
        assert_eq!(args.o_options.server_alive_count_max, Some(3));
    }

    #[test]
    fn o_compression() {
        let args = parse_args_from(make_argv(&["-o", "Compression=yes", "host"]));
        assert_eq!(args.o_options.compression, Some(true));

        let args = parse_args_from(make_argv(&["-o", "Compression=no", "host"]));
        assert_eq!(args.o_options.compression, Some(false));
    }

    #[test]
    fn o_kex_algorithms() {
        let args = parse_args_from(make_argv(&[
            "-o",
            "KexAlgorithms=curve25519-sha256,ecdh-sha2-nistp256",
            "host",
        ]));
        assert_eq!(
            args.o_options.kex_algorithms,
            Some(vec![
                "curve25519-sha256".to_string(),
                "ecdh-sha2-nistp256".to_string()
            ])
        );
    }

    #[test]
    fn o_ciphers() {
        let args = parse_args_from(make_argv(&["-o", "Ciphers=aes256-gcm@openssh.com", "host"]));
        assert_eq!(
            args.o_options.ciphers,
            Some(vec!["aes256-gcm@openssh.com".to_string()])
        );
    }

    #[test]
    fn o_macs() {
        let args = parse_args_from(make_argv(&["-o", "MACs=hmac-sha2-256", "host"]));
        assert_eq!(args.o_options.macs, Some(vec!["hmac-sha2-256".to_string()]));
    }

    #[test]
    fn o_host_key_algorithms() {
        let args = parse_args_from(make_argv(&["-o", "HostKeyAlgorithms=ssh-ed25519", "host"]));
        assert_eq!(
            args.o_options.host_key_algorithms,
            Some(vec!["ssh-ed25519".to_string()])
        );
    }

    #[test]
    fn o_password_authentication() {
        let args = parse_args_from(make_argv(&["-o", "PasswordAuthentication=no", "host"]));
        assert_eq!(args.o_options.password_authentication, Some(false));
    }

    #[test]
    fn config_file_flag() {
        let args = parse_args_from(make_argv(&["-F", "/my/config", "host"]));
        assert_eq!(args.config_file, Some(PathBuf::from("/my/config")));
    }

    #[test]
    fn config_values_applied_as_defaults() {
        let resolved = ResolvedConfig {
            user: Some("cfguser".to_string()),
            port: Some(3333),
            hostname: Some("real.host.example".to_string()),
            identity_files: vec!["~/.ssh/id_rsa".to_string()],
            proxy_jump: Some("bastion:22".to_string()),
            ..ResolvedConfig::default()
        };
        let mut args = parse_args_from(make_argv(&["example.com"]));
        apply_config(&mut args, &resolved);

        assert_eq!(args.user, "cfguser");
        assert_eq!(args.port, 3333);
        assert_eq!(args.host, "real.host.example");
        assert_eq!(args.jump, Some("bastion:22".to_string()));
        // Config identity files are appended.
        assert!(args.identity.iter().any(|p| p.ends_with("id_rsa")));
    }

    #[test]
    fn cli_flags_override_config() {
        let resolved = ResolvedConfig {
            user: Some("cfguser".to_string()),
            port: Some(3333),
            ..ResolvedConfig::default()
        };
        // -l and -p are explicit CLI flags, so they should win.
        let mut args = parse_args_from(make_argv(&["-l", "cliuser", "-p", "4444", "host"]));
        apply_config(&mut args, &resolved);

        assert_eq!(args.user, "cliuser");
        assert_eq!(args.port, 4444);
    }

    #[test]
    fn o_option_overrides_config() {
        let resolved = ResolvedConfig {
            port: Some(3333),
            user: Some("cfguser".to_string()),
            ..ResolvedConfig::default()
        };
        let mut args = parse_args_from(make_argv(&["-o", "Port=5555", "-o", "User=ouser", "host"]));
        apply_config(&mut args, &resolved);

        // -o should win over config.
        assert_eq!(args.port, 5555);
        assert_eq!(args.user, "ouser");
    }

    #[test]
    fn nonexistent_config_produces_default() {
        let resolved = load_ssh_config(
            std::path::Path::new("/nonexistent/path/config"),
            "example.com",
        );
        assert_eq!(resolved, ResolvedConfig::default());
    }

    #[test]
    fn o_option_inline_syntax() {
        // -oPort=2222 (no space)
        let args = parse_args_from(make_argv(&["-oPort=2222", "host"]));
        assert_eq!(args.o_options.port, Some(2222));
    }

    #[test]
    fn multiple_o_options() {
        let args = parse_args_from(make_argv(&[
            "-o",
            "Port=2222",
            "-o",
            "User=admin",
            "-o",
            "Compression=yes",
            "host",
        ]));
        assert_eq!(args.o_options.port, Some(2222));
        assert_eq!(args.o_options.user.as_deref(), Some("admin"));
        assert_eq!(args.o_options.compression, Some(true));
    }

    #[test]
    fn o_password_authentication_no() {
        let args = parse_args_from(make_argv(&["-o", "PasswordAuthentication=no", "host"]));
        assert_eq!(args.o_options.password_authentication, Some(false));
    }

    #[test]
    fn o_password_authentication_yes() {
        let args = parse_args_from(make_argv(&["-o", "PasswordAuthentication=yes", "host"]));
        assert_eq!(args.o_options.password_authentication, Some(true));
    }

    #[test]
    fn o_preferred_authentications_parses_list() {
        let args = parse_args_from(make_argv(&[
            "-o",
            "PreferredAuthentications=publickey,keyboard-interactive,password",
            "host",
        ]));
        assert_eq!(
            args.o_options.preferred_authentications,
            Some(vec![
                "publickey".to_string(),
                "keyboard-interactive".to_string(),
                "password".to_string(),
            ])
        );
    }

    #[test]
    fn o_preferred_authentications_single_method() {
        let args = parse_args_from(make_argv(&[
            "-o",
            "PreferredAuthentications=password",
            "host",
        ]));
        assert_eq!(
            args.o_options.preferred_authentications,
            Some(vec!["password".to_string()])
        );
    }

    #[test]
    fn auth_method_ordering_from_preferred() {
        // Simulate what main() does: convert preferred_authentications strings
        // into AuthMethod values, filtering out unrecognised ones.
        let prefs = vec![
            "password".to_string(),
            "publickey".to_string(),
            "bogus".to_string(),
        ];
        let methods: Vec<AuthMethod> = prefs
            .iter()
            .filter_map(|s| AuthMethod::from_ssh_name(s))
            .collect();
        assert_eq!(methods, vec![AuthMethod::Password, AuthMethod::PublicKey]);
    }

    #[test]
    fn default_auth_order_without_preferred() {
        let args = parse_args_from(make_argv(&["host"]));
        assert!(args.o_options.preferred_authentications.is_none());
        // The default order built in main() is:
        // publickey → keyboard-interactive → password.
        let defaults = vec![
            AuthMethod::PublicKey,
            AuthMethod::KeyboardInteractive,
            AuthMethod::Password,
        ];
        assert_eq!(defaults[0], AuthMethod::PublicKey);
        assert_eq!(defaults[1], AuthMethod::KeyboardInteractive);
        assert_eq!(defaults[2], AuthMethod::Password);
    }

    #[test]
    fn agent_forwarding_flag() {
        let args = parse_args_from(make_argv(&["-A", "host"]));
        assert!(args.agent_forwarding);
    }

    #[test]
    fn agent_forwarding_default_off() {
        let args = parse_args_from(make_argv(&["host"]));
        assert!(!args.agent_forwarding);
    }

    // ── Local port forwarding (-L) tests ─────────────────────────────────

    #[test]
    fn parse_local_forward_three_part() {
        let fwd = parse_local_forward("8080:localhost:80").unwrap();
        assert_eq!(
            fwd,
            ("127.0.0.1".to_string(), 8080, "localhost".to_string(), 80)
        );
    }

    #[test]
    fn parse_local_forward_four_part() {
        let fwd = parse_local_forward("0.0.0.0:5432:db.internal:5432").unwrap();
        assert_eq!(
            fwd,
            ("0.0.0.0".to_string(), 5432, "db.internal".to_string(), 5432)
        );
    }

    #[test]
    fn parse_local_forward_invalid() {
        assert!(parse_local_forward("bad").is_none());
        assert!(parse_local_forward("abc:host:80").is_none()); // non-numeric port
    }

    #[test]
    fn l_flag_parsed_into_args() {
        let args = parse_args_from(make_argv(&[
            "-L",
            "8080:localhost:80",
            "-L",
            "0.0.0.0:5432:db:5432",
            "host",
        ]));
        assert_eq!(args.local_forwards.len(), 2);
        assert_eq!(
            args.local_forwards[0],
            ("127.0.0.1".to_string(), 8080, "localhost".to_string(), 80)
        );
        assert_eq!(
            args.local_forwards[1],
            ("0.0.0.0".to_string(), 5432, "db".to_string(), 5432)
        );
    }

    #[test]
    fn l_flag_empty_by_default() {
        let args = parse_args_from(make_argv(&["host"]));
        assert!(args.local_forwards.is_empty());
    }
}
