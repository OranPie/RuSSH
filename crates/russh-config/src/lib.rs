//! OpenSSH-style configuration parser and resolver for RuSSH.
//!
//! Parses `~/.ssh/config`-style files and resolves per-host settings with
//! full OpenSSH first-match-wins semantics.
//!
//! ## Parsing
//!
//! [`parse_config`] reads a config string line-by-line, returning a
//! [`ConfigFile`] whose `.directives` field holds every recognized directive
//! plus [`Directive::Unknown`] for unrecognized keywords (preserved without
//! error).
//!
//! ## Resolution
//!
//! [`ConfigFile::resolve_for_host`] applies all matching `Host` blocks to
//! produce a [`ResolvedConfig`]:
//!
//! - **First-match-wins** — for each key, only the first value seen across
//!   all matching blocks is kept (OpenSSH semantics).
//! - **Pattern matching** — [`matches_host_patterns`] supports `*` / `?`
//!   wildcards and `!negation` patterns per OpenSSH rules.
//! - **Token expansion** — `%h` → hostname, `%u` → username, `%%` → `%`.
//! - **Tilde expansion** — leading `~/` in path values expanded to `$HOME`.
//!
//! ## Example
//!
//! ```rust
//! use russh_config::parse_config;
//!
//! let cfg = parse_config("
//! Host bastion
//!   User admin
//!   Port 2222
//!   IdentityFile ~/.ssh/id_ed25519
//! ").unwrap();
//!
//! let resolved = cfg.resolve_for_host("bastion");
//! assert_eq!(resolved.port, Some(2222));
//! ```

use std::collections::BTreeMap;

use russh_core::{RusshError, RusshErrorCategory};

/// Parsed config file with directives and deterministic warnings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigFile {
    pub directives: Vec<Directive>,
    pub warnings: Vec<ConfigWarning>,
}

impl ConfigFile {
    #[must_use]
    pub fn new() -> Self {
        Self {
            directives: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Produce a simple key-value snapshot for common directives.
    #[must_use]
    pub fn normalized_map(&self) -> BTreeMap<String, String> {
        let mut normalized = BTreeMap::new();

        for directive in &self.directives {
            match directive {
                Directive::Host(pattern) => {
                    normalized.insert("Host".to_string(), pattern.clone());
                }
                Directive::User(user) => {
                    normalized.insert("User".to_string(), user.clone());
                }
                Directive::Port(port) => {
                    normalized.insert("Port".to_string(), port.to_string());
                }
                Directive::HostName(host_name) => {
                    normalized.insert("HostName".to_string(), host_name.clone());
                }
                Directive::IdentityFile(path) => {
                    normalized.insert("IdentityFile".to_string(), path.clone());
                }
                Directive::ForwardAgent(enabled) => {
                    normalized.insert("ForwardAgent".to_string(), enabled.to_string());
                }
                Directive::LocalForward { bind, target } => {
                    normalized.insert("LocalForward".to_string(), format!("{bind} {target}"));
                }
                Directive::RemoteForward { bind, target } => {
                    normalized.insert("RemoteForward".to_string(), format!("{bind} {target}"));
                }
                Directive::KexAlgorithms(list) => {
                    normalized.insert("KexAlgorithms".to_string(), list.join(","));
                }
                Directive::Ciphers(list) => {
                    normalized.insert("Ciphers".to_string(), list.join(","));
                }
                Directive::Macs(list) => {
                    normalized.insert("MACs".to_string(), list.join(","));
                }
                Directive::ServerAliveInterval(seconds) => {
                    normalized.insert("ServerAliveInterval".to_string(), seconds.to_string());
                }
                Directive::Include(path) => {
                    normalized.insert("Include".to_string(), path.clone());
                }
                Directive::ProxyJump(v) => {
                    normalized.insert("ProxyJump".to_string(), v.clone());
                }
                Directive::ControlMaster(v) => {
                    normalized.insert("ControlMaster".to_string(), v.clone());
                }
                Directive::ControlPath(v) => {
                    normalized.insert("ControlPath".to_string(), v.clone());
                }
                Directive::AllowUsers(users) => {
                    normalized.insert("AllowUsers".to_string(), users.join(" "));
                }
                Directive::DenyUsers(users) => {
                    normalized.insert("DenyUsers".to_string(), users.join(" "));
                }
                Directive::LoginGraceTime(seconds) => {
                    normalized.insert("LoginGraceTime".to_string(), seconds.to_string());
                }
                Directive::Unknown(unknown) => {
                    normalized.insert(
                        format!("Unknown:{}", unknown.keyword),
                        unknown.arguments.join(" "),
                    );
                }
            }
        }

        normalized
    }
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self::new()
    }
}

/// Known directives plus preserved unknown entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Directive {
    Host(String),
    User(String),
    Port(u16),
    HostName(String),
    IdentityFile(String),
    ForwardAgent(bool),
    LocalForward { bind: String, target: String },
    RemoteForward { bind: String, target: String },
    KexAlgorithms(Vec<String>),
    Ciphers(Vec<String>),
    Macs(Vec<String>),
    ServerAliveInterval(u64),
    Include(String),
    ProxyJump(String),
    ControlMaster(String),
    ControlPath(String),
    AllowUsers(Vec<String>),
    DenyUsers(Vec<String>),
    LoginGraceTime(u64),
    Unknown(UnknownDirective),
}

/// A parsed Host or Match block from an SSH config file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostBlock {
    /// Patterns from `Host` line, e.g. ["*.example.com", "!dev.example.com"]
    /// Empty vec means the default/global block (before any Host line)
    pub patterns: Vec<String>,
    /// True if this is a Match block (not Host)
    pub is_match: bool,
    /// Directives under this block
    pub directives: Vec<Directive>,
}

/// The result of resolving a config for a specific host.
/// First-match-wins: for each key, only the first value seen (across matching blocks) is kept.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolvedConfig {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub hostname: Option<String>,
    pub identity_files: Vec<String>,
    pub forward_agent: Option<bool>,
    pub local_forwards: Vec<(String, String)>,
    pub remote_forwards: Vec<(String, String)>,
    pub kex_algorithms: Option<Vec<String>>,
    pub ciphers: Option<Vec<String>>,
    pub macs: Option<Vec<String>>,
    pub server_alive_interval: Option<u64>,
    pub proxy_jump: Option<String>,
    pub control_master: Option<String>,
    pub control_path: Option<String>,
    pub allow_users: Option<Vec<String>>,
    pub deny_users: Option<Vec<String>>,
    pub login_grace_time: Option<u64>,
    pub extra: std::collections::BTreeMap<String, String>,
}

/// Unknown directive representation preserved for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownDirective {
    pub keyword: String,
    pub arguments: Vec<String>,
    pub line: usize,
}

/// Parser warnings with stable message semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigWarning {
    pub line: usize,
    pub message: String,
}

/// Parse OpenSSH-like config text into a typed AST.
pub fn parse_config(input: &str) -> Result<ConfigFile, RusshError> {
    let mut file = ConfigFile::new();

    for (index, original_line) in input.lines().enumerate() {
        let line_number = index + 1;

        let line = strip_comment(original_line).trim();
        if line.is_empty() {
            continue;
        }

        let tokens: Vec<String> = line.split_whitespace().map(ToOwned::to_owned).collect();
        let keyword = tokens.first().ok_or_else(|| {
            RusshError::new(
                RusshErrorCategory::Config,
                format!("line {line_number}: missing directive keyword"),
            )
        })?;
        let args = &tokens[1..];

        let directive = match keyword.to_ascii_lowercase().as_str() {
            "host" => Directive::Host(join_args(args, line_number, "Host")?),
            "user" => Directive::User(join_args(args, line_number, "User")?),
            "port" => Directive::Port(parse_integer(args, line_number, "Port")?),
            "hostname" => Directive::HostName(join_args(args, line_number, "HostName")?),
            "identityfile" => {
                Directive::IdentityFile(join_args(args, line_number, "IdentityFile")?)
            }
            "forwardagent" => {
                Directive::ForwardAgent(parse_bool(args, line_number, "ForwardAgent")?)
            }
            "localforward" => {
                let (bind, target) = parse_two_values(args, line_number, "LocalForward")?;
                Directive::LocalForward { bind, target }
            }
            "remoteforward" => {
                let (bind, target) = parse_two_values(args, line_number, "RemoteForward")?;
                Directive::RemoteForward { bind, target }
            }
            "kexalgorithms" => {
                Directive::KexAlgorithms(parse_csv(args, line_number, "KexAlgorithms")?)
            }
            "ciphers" => Directive::Ciphers(parse_csv(args, line_number, "Ciphers")?),
            "macs" => Directive::Macs(parse_csv(args, line_number, "MACs")?),
            "serveraliveinterval" => Directive::ServerAliveInterval(parse_integer(
                args,
                line_number,
                "ServerAliveInterval",
            )?),
            "include" => Directive::Include(join_args(args, line_number, "Include")?),
            "proxyjump" => Directive::ProxyJump(join_args(args, line_number, "ProxyJump")?),
            "controlmaster" => {
                Directive::ControlMaster(join_args(args, line_number, "ControlMaster")?)
            }
            "controlpath" => Directive::ControlPath(join_args(args, line_number, "ControlPath")?),
            "allowusers" => {
                Directive::AllowUsers(parse_space_list(args, line_number, "AllowUsers")?)
            }
            "denyusers" => Directive::DenyUsers(parse_space_list(args, line_number, "DenyUsers")?),
            "logingracetime" => {
                Directive::LoginGraceTime(parse_integer(args, line_number, "LoginGraceTime")?)
            }
            _ => {
                file.warnings.push(ConfigWarning {
                    line: line_number,
                    message: format!("unsupported directive '{keyword}' preserved as Unknown"),
                });
                Directive::Unknown(UnknownDirective {
                    keyword: keyword.to_string(),
                    arguments: args.to_vec(),
                    line: line_number,
                })
            }
        };

        file.directives.push(directive);
    }

    Ok(file)
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(head, _)| head)
}

fn join_args(args: &[String], line: usize, key: &str) -> Result<String, RusshError> {
    if args.is_empty() {
        return Err(RusshError::new(
            RusshErrorCategory::Config,
            format!("line {line}: {key} requires at least one value"),
        ));
    }
    Ok(args.join(" "))
}

fn parse_bool(args: &[String], line: usize, key: &str) -> Result<bool, RusshError> {
    let value = join_args(args, line, key)?;
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" => Ok(true),
        "no" | "false" | "off" => Ok(false),
        _ => Err(RusshError::new(
            RusshErrorCategory::Config,
            format!("line {line}: {key} expects yes/no"),
        )),
    }
}

fn parse_two_values(
    args: &[String],
    line: usize,
    key: &str,
) -> Result<(String, String), RusshError> {
    if args.len() != 2 {
        return Err(RusshError::new(
            RusshErrorCategory::Config,
            format!("line {line}: {key} expects exactly two values"),
        ));
    }

    Ok((args[0].clone(), args[1].clone()))
}

fn parse_integer<T>(args: &[String], line: usize, key: &str) -> Result<T, RusshError>
where
    T: std::str::FromStr,
{
    let value = join_args(args, line, key)?;
    value.parse::<T>().map_err(|_| {
        RusshError::new(
            RusshErrorCategory::Config,
            format!("line {line}: {key} expects an integer"),
        )
    })
}

fn parse_space_list(args: &[String], line: usize, key: &str) -> Result<Vec<String>, RusshError> {
    if args.is_empty() {
        return Err(RusshError::new(
            RusshErrorCategory::Config,
            format!("line {line}: {key} requires at least one username"),
        ));
    }
    Ok(args.to_vec())
}

fn parse_csv(args: &[String], line: usize, key: &str) -> Result<Vec<String>, RusshError> {
    let value = join_args(args, line, key)?;
    let items: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    if items.is_empty() {
        return Err(RusshError::new(
            RusshErrorCategory::Config,
            format!("line {line}: {key} expects at least one algorithm"),
        ));
    }

    Ok(items)
}

impl ConfigFile {
    /// Parse the flat directive list into Host blocks.
    /// Directives before the first Host line form the "global" block (patterns = []).
    #[must_use]
    pub fn into_host_blocks(&self) -> Vec<HostBlock> {
        let mut blocks: Vec<HostBlock> = Vec::new();
        let mut current_patterns: Vec<String> = Vec::new();
        let mut current_directives: Vec<Directive> = Vec::new();
        let mut in_host_block = false;

        for directive in &self.directives {
            match directive {
                Directive::Host(pattern_str) => {
                    if in_host_block || !current_directives.is_empty() {
                        blocks.push(HostBlock {
                            patterns: current_patterns.clone(),
                            is_match: false,
                            directives: std::mem::take(&mut current_directives),
                        });
                    }
                    current_patterns = pattern_str
                        .split_whitespace()
                        .map(ToOwned::to_owned)
                        .collect();
                    in_host_block = true;
                }
                other => {
                    current_directives.push(other.clone());
                }
            }
        }

        if !current_directives.is_empty() || in_host_block {
            blocks.push(HostBlock {
                patterns: current_patterns,
                is_match: false,
                directives: current_directives,
            });
        }

        blocks
    }

    /// Resolve configuration for a specific hostname using first-match-wins semantics.
    ///
    /// - Global directives (before any Host line) always apply
    /// - Host blocks apply only when the hostname matches their patterns
    /// - For each setting, the first value encountered wins
    /// - Path values have `~` expanded to the HOME environment variable
    /// - String values support `%h` → hostname, `%u` → username (from $USER/$LOGNAME)
    #[must_use]
    pub fn resolve_for_host(&self, hostname: &str) -> ResolvedConfig {
        let blocks = self.into_host_blocks();
        let mut resolved = ResolvedConfig::default();

        for block in &blocks {
            let applies =
                block.patterns.is_empty() || matches_host_patterns(&block.patterns, hostname);
            if !applies {
                continue;
            }
            for directive in &block.directives {
                apply_directive_first_match(directive, &mut resolved, hostname);
            }
        }

        resolved
    }
}

fn apply_directive_first_match(
    directive: &Directive,
    resolved: &mut ResolvedConfig,
    hostname: &str,
) {
    let home = std::env::var("HOME").unwrap_or_default();
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();

    match directive {
        Directive::User(v) if resolved.user.is_none() => {
            resolved.user = Some(expand_tokens(v, hostname, &user));
        }
        Directive::Port(v) if resolved.port.is_none() => {
            resolved.port = Some(*v);
        }
        Directive::HostName(v) if resolved.hostname.is_none() => {
            resolved.hostname = Some(expand_tokens(v, hostname, &user));
        }
        Directive::IdentityFile(v) => {
            resolved
                .identity_files
                .push(expand_tilde(&expand_tokens(v, hostname, &user), &home));
        }
        Directive::ForwardAgent(v) if resolved.forward_agent.is_none() => {
            resolved.forward_agent = Some(*v);
        }
        Directive::LocalForward { bind, target } => {
            resolved.local_forwards.push((bind.clone(), target.clone()));
        }
        Directive::RemoteForward { bind, target } => {
            resolved
                .remote_forwards
                .push((bind.clone(), target.clone()));
        }
        Directive::KexAlgorithms(v) if resolved.kex_algorithms.is_none() => {
            resolved.kex_algorithms = Some(v.clone());
        }
        Directive::Ciphers(v) if resolved.ciphers.is_none() => {
            resolved.ciphers = Some(v.clone());
        }
        Directive::Macs(v) if resolved.macs.is_none() => {
            resolved.macs = Some(v.clone());
        }
        Directive::ServerAliveInterval(v) if resolved.server_alive_interval.is_none() => {
            resolved.server_alive_interval = Some(*v);
        }
        Directive::ProxyJump(v) if resolved.proxy_jump.is_none() => {
            resolved.proxy_jump = Some(expand_tokens(v, hostname, &user));
        }
        Directive::ControlMaster(v) if resolved.control_master.is_none() => {
            resolved.control_master = Some(v.clone());
        }
        Directive::ControlPath(v) if resolved.control_path.is_none() => {
            resolved.control_path = Some(expand_tilde(&expand_tokens(v, hostname, &user), &home));
        }
        Directive::AllowUsers(v) if resolved.allow_users.is_none() => {
            resolved.allow_users = Some(v.clone());
        }
        Directive::DenyUsers(v) if resolved.deny_users.is_none() => {
            resolved.deny_users = Some(v.clone());
        }
        Directive::LoginGraceTime(v) if resolved.login_grace_time.is_none() => {
            resolved.login_grace_time = Some(*v);
        }
        Directive::Unknown(u) => {
            resolved
                .extra
                .entry(u.keyword.clone())
                .or_insert_with(|| u.arguments.join(" "));
        }
        _ => {} // directive already set (first-match-wins) or Include (not resolved here)
    }
}

/// Expand `~` at the start of a path to the HOME directory.
fn expand_tilde(path: &str, home: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/") {
        format!("{home}/{stripped}")
    } else if path == "~" {
        home.to_string()
    } else {
        path.to_string()
    }
}

/// Expand SSH config tokens: %h=hostname, %u=username, %%=literal %
fn expand_tokens(value: &str, hostname: &str, user: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.next() {
                Some('h') => result.push_str(hostname),
                Some('u') => result.push_str(user),
                Some('%') => result.push('%'),
                Some(other) => {
                    result.push('%');
                    result.push(other);
                }
                None => result.push('%'),
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Returns true if `hostname` matches any non-negated pattern AND is not excluded
/// by any negated pattern (patterns starting with `!`).
///
/// Rules:
/// - `*` matches any sequence (including empty)
/// - `?` matches exactly one character
/// - Patterns starting with `!` are negation patterns
/// - If any negation pattern matches, the host is excluded regardless of positive matches
/// - Pattern matching is case-insensitive
pub fn matches_host_patterns(patterns: &[String], hostname: &str) -> bool {
    let mut positive_match = false;
    let hostname_lower = hostname.to_ascii_lowercase();

    for pattern in patterns {
        if let Some(neg_pat) = pattern.strip_prefix('!') {
            if glob_match(neg_pat, &hostname_lower) {
                return false;
            }
        } else if glob_match(pattern, &hostname_lower) {
            positive_match = true;
        }
    }

    positive_match
}

/// Simple SSH-style glob matching (`*` = any sequence, `?` = any single char).
/// Case-insensitive (caller should lowercase both inputs).
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pat = pattern.to_ascii_lowercase();
    glob_match_impl(pat.as_bytes(), value.as_bytes())
}

fn glob_match_impl(pattern: &[u8], value: &[u8]) -> bool {
    match (pattern.first(), value.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            glob_match_impl(&pattern[1..], value)
                || (!value.is_empty() && glob_match_impl(pattern, &value[1..]))
        }
        (Some(b'?'), Some(_)) => glob_match_impl(&pattern[1..], &value[1..]),
        (Some(p), Some(v)) if p == v => glob_match_impl(&pattern[1..], &value[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{glob_match, matches_host_patterns, parse_config, Directive};

    #[test]
    fn parser_handles_known_and_unknown_directives() {
        let text = "\
Host example\n\
User alice\n\
Port 22\n\
UnknownDirective value\n";

        let file = parse_config(text).expect("parse should succeed");
        assert_eq!(file.directives.len(), 4);
        assert_eq!(file.warnings.len(), 1);
        assert!(matches!(file.directives[0], Directive::Host(_)));
        assert!(matches!(file.directives[3], Directive::Unknown(_)));
    }

    #[test]
    fn parser_rejects_invalid_bool() {
        let text = "ForwardAgent maybe\n";
        let err = parse_config(text).expect_err("parse should fail");
        assert!(err.message().contains("ForwardAgent expects yes/no"));
    }

    #[test]
    fn host_glob_matches_wildcard() {
        assert!(glob_match("*.example.com", "foo.example.com"));
        assert!(glob_match("*.example.com", "bar.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn host_glob_question_mark() {
        assert!(glob_match("host?", "host1"));
        assert!(!glob_match("host?", "host12"));
    }

    #[test]
    fn host_pattern_negation_excludes() {
        let patterns = vec!["*.example.com".to_string(), "!dev.example.com".to_string()];
        assert!(matches_host_patterns(&patterns, "prod.example.com"));
        assert!(!matches_host_patterns(&patterns, "dev.example.com"));
    }

    #[test]
    fn resolve_first_match_wins() {
        let config = parse_config(
            "
Host *.example.com
  User alice
  Port 2222
Host prod.example.com
  User root
  Port 22
",
        )
        .expect("parse should succeed");

        let resolved = config.resolve_for_host("prod.example.com");
        assert_eq!(resolved.user.as_deref(), Some("alice")); // first match wins
        assert_eq!(resolved.port, Some(2222));
    }

    #[test]
    fn resolve_global_directives_always_apply() {
        let config = parse_config(
            "
ServerAliveInterval 30
Host special
  Port 2222
",
        )
        .expect("parse should succeed");

        let resolved = config.resolve_for_host("other.host");
        assert_eq!(resolved.server_alive_interval, Some(30));
        assert_eq!(resolved.port, None);
    }

    #[test]
    fn resolve_tilde_expansion_in_identity_file() {
        let config = parse_config(
            "
Host *
  IdentityFile ~/.ssh/id_ed25519
",
        )
        .expect("parse should succeed");

        let resolved = config.resolve_for_host("any.host");
        assert!(!resolved.identity_files.is_empty());
        assert!(!resolved.identity_files[0].starts_with('~'));
    }

    #[test]
    fn resolve_token_substitution() {
        let config = parse_config(
            "
Host myhost
  HostName %h.internal.example.com
",
        )
        .expect("parse should succeed");

        let resolved = config.resolve_for_host("myhost");
        assert_eq!(
            resolved.hostname.as_deref(),
            Some("myhost.internal.example.com")
        );
    }

    #[test]
    fn parse_and_resolve_proxyjump() {
        let config = parse_config(
            "
Host target
  ProxyJump bastion.example.com
  User alice
",
        )
        .expect("parse should succeed");

        let resolved = config.resolve_for_host("target");
        assert_eq!(resolved.proxy_jump.as_deref(), Some("bastion.example.com"));
    }

    #[test]
    fn parse_and_resolve_control_master() {
        let config = parse_config(
            "
Host *
  ControlMaster auto
  ControlPath /tmp/ssh-%h-%u.sock
",
        )
        .expect("parse should succeed");

        let resolved = config.resolve_for_host("myhost");
        assert_eq!(resolved.control_master.as_deref(), Some("auto"));
        let cp = resolved.control_path.as_deref().unwrap_or("");
        assert!(cp.contains("myhost"), "ControlPath should expand %h");
    }

    #[test]
    fn control_path_tilde_and_tokens() {
        let config = parse_config(
            "
Host dev
  ControlPath ~/.ssh/cm_%h.sock
",
        )
        .expect("parse should succeed");

        let resolved = config.resolve_for_host("dev");
        let cp = resolved.control_path.as_deref().unwrap_or("");
        assert!(!cp.starts_with('~'), "tilde should be expanded");
        assert!(
            cp.ends_with("cm_dev.sock"),
            "token %h should expand to hostname"
        );
    }

    #[test]
    fn proxyjump_none_value_accepted() {
        let config = parse_config(
            "
Host direct
  ProxyJump none
",
        )
        .expect("parse should succeed");

        assert_eq!(
            config.resolve_for_host("direct").proxy_jump.as_deref(),
            Some("none")
        );
    }

    #[test]
    fn parse_and_resolve_login_grace_time() {
        let config = parse_config(
            "
LoginGraceTime 60
Host special
  LoginGraceTime 30
",
        )
        .expect("parse should succeed");

        // Global directive applies to any host
        let resolved = config.resolve_for_host("other.host");
        assert_eq!(resolved.login_grace_time, Some(60));

        // First-match-wins: global (60) beats host-specific (30)
        let resolved = config.resolve_for_host("special");
        assert_eq!(resolved.login_grace_time, Some(60));
    }
}
