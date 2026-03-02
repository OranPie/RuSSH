//! OpenSSH-style configuration parser and normalization helpers.

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
    Unknown(UnknownDirective),
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

#[cfg(test)]
mod tests {
    use super::{Directive, parse_config};

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
}
