//! Create k0s-style cluster join tokens (`dioramactl token create`).

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use diorama_pki::token::{JoinRole, JoinToken};

pub const HELP: &str = "Create a cluster join token for controller or worker nodes.\n\nUsage:\n  dioramactl token create [--role controller|worker] [--expiry <duration>] [--path <node-data>] [--api-endpoint <url>] [--peer-addr <ip:port>]\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenOptions {
    pub role: JoinRole,
    pub expiry_secs: Option<u64>,
    pub path: PathBuf,
    pub api_endpoint: Option<String>,
    pub peer_addr: Option<SocketAddr>,
}

impl Default for TokenOptions {
    fn default() -> Self {
        Self {
            role: JoinRole::Worker,
            expiry_secs: None,
            path: crate::DEFAULT_DATA_PATH.into(),
            api_endpoint: None,
            peer_addr: None,
        }
    }
}

fn parse_duration_secs(raw: &str) -> Result<Option<u64>, crate::ParseError> {
    let trimmed = raw.trim();
    if trimmed == "0" || trimmed == "0s" {
        return Ok(None);
    }
    let (digits, multiplier) = if let Some(h) = trimmed.strip_suffix('h') {
        (h, 3600u64)
    } else if let Some(m) = trimmed.strip_suffix('m') {
        (m, 60u64)
    } else if let Some(s) = trimmed.strip_suffix('s') {
        (s, 1u64)
    } else {
        (trimmed, 1u64)
    };
    let val = digits
        .parse::<u64>()
        .map_err(|_| crate::ParseError::UnknownFlag)?;
    Ok(Some(val.saturating_mul(multiplier)))
}

pub fn parse(args: &[String]) -> Result<TokenOptions, crate::ParseError> {
    if args.first().map(String::as_str) != Some("create") {
        return Err(crate::ParseError::UnknownCommand);
    }
    let mut options = TokenOptions::default();
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        let (key, value) = match arg.split_once('=') {
            Some(pair) => pair,
            None => (
                arg.as_str(),
                rest.next().ok_or(crate::ParseError::UnknownFlag)?.as_str(),
            ),
        };
        match key {
            "--role" => {
                options.role = value
                    .parse::<JoinRole>()
                    .map_err(|_| crate::ParseError::UnknownFlag)?;
            },
            "--expiry" => {
                options.expiry_secs = parse_duration_secs(value)?;
            },
            "--path" => {
                options.path = PathBuf::from(value);
            },
            "--api-endpoint" if !value.is_empty() => {
                options.api_endpoint = Some(value.to_string());
            },
            "--peer-addr" => {
                options.peer_addr = Some(
                    value
                        .parse::<SocketAddr>()
                        .map_err(|_| crate::ParseError::UnknownFlag)?,
                );
            },
            _ => return Err(crate::ParseError::UnknownFlag),
        }
    }
    Ok(options)
}

fn discover_endpoints_from_pki(pki_dir: &Path) -> (String, SocketAddr) {
    let default_api = "https://127.0.0.1:6443".to_string();
    let default_peer: SocketAddr = "127.0.0.1:2380".parse().unwrap();

    let Ok(kubeconfig) = std::fs::read_to_string(pki_dir.join("admin.kubeconfig")) else {
        return (default_api, default_peer);
    };
    for line in kubeconfig.lines() {
        if let Some(server) = line.trim().strip_prefix("server:") {
            let api = server.trim().trim_matches('"').to_string();
            if let Some(host_port) = api.strip_prefix("https://")
                && let Ok(sock) = host_port.parse::<SocketAddr>()
            {
                return (api, SocketAddr::new(sock.ip(), 2380));
            }
            return (api, default_peer);
        }
    }
    (default_api, default_peer)
}

pub fn execute_token(
    options: &TokenOptions,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let pki_dir = options.path.join("pki");
    let (discovered_api, discovered_peer) = discover_endpoints_from_pki(&pki_dir);
    let api_endpoint = options.api_endpoint.clone().unwrap_or(discovered_api);
    let peer_addr = options.peer_addr.unwrap_or(discovered_peer);

    match JoinToken::create_from_pki_dir(
        &pki_dir,
        options.role,
        api_endpoint,
        peer_addr,
        options.expiry_secs,
    )
    .and_then(|token| token.encode())
    {
        Ok(encoded) => {
            writeln!(stdout, "{encoded}")?;
            Ok(0)
        },
        Err(err) => {
            writeln!(stderr, "[fail] token create: {err}")?;
            Ok(1)
        },
    }
}
