//! russh-web — browser-based SSH terminal server.
//!
//! Usage:
//!   russh-web [OPTIONS]
//!
//! Options:
//!   -b ADDR     Bind address (default: 127.0.0.1)
//!   -p PORT     HTTP port (default: 8080)
//!   -v          Increase verbosity (-v, -vv, -vvv)
//!   -q          Quiet mode
//!   --help      Print this help

use std::process;
use std::sync::Arc;

use russh_observability::{StderrLogger, VerboseLevel};

struct CliArgs {
    bind: String,
    port: u16,
    verbose: u8,
    quiet: bool,
}

fn usage() -> ! {
    eprintln!(
        "Usage: russh-web [OPTIONS]\n\
         \n\
         Options:\n\
         \x20 -b ADDR     Bind address (default: 127.0.0.1)\n\
         \x20 -p PORT     HTTP port (default: 8080)\n\
         \x20 -v          Increase verbosity\n\
         \x20 -q          Quiet mode\n\
         \x20 --help      Print this help"
    );
    process::exit(1);
}

fn parse_args() -> CliArgs {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut bind = "127.0.0.1".to_string();
    let mut port: u16 = 8080;
    let mut verbose: u8 = 0;
    let mut quiet = false;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--help" => usage(),
            "-b" => {
                i += 1;
                bind = argv.get(i).cloned().unwrap_or(bind);
            }
            "-p" => {
                i += 1;
                port = argv.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| {
                    eprintln!("error: -p requires a port number");
                    process::exit(1);
                });
            }
            "-v" => verbose += 1,
            "-vv" => verbose += 2,
            "-vvv" => verbose += 3,
            "-q" | "--quiet" => quiet = true,
            _ => {}
        }
        i += 1;
    }

    CliArgs {
        bind,
        port,
        verbose,
        quiet,
    }
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let level = VerboseLevel::from_flags(args.verbose, args.quiet);
    let log = Arc::new(StderrLogger::new(level, "russh-web"));

    let addr = format!("{}:{}", args.bind, args.port);
    let app = russh_web::app(log.clone());

    eprintln!("russh-web: listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("russh-web: bind failed: {e}");
            process::exit(1);
        });

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("russh-web: server error: {e}");
        process::exit(1);
    });
}
