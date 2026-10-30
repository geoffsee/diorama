//! Manage k0s-style cluster join tokens (`dioramactl token create|list|invalidate`).

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use diorama_datastore::{DatastoreClient, DatastoreConfig, DatastoreEngine, DatastoreError};
use diorama_pki::token::{JoinRole, JoinToken};

pub const HELP: &str = "Manage cluster join tokens.\n\nUsage:\n  dioramactl token create [--role controller|worker] [--expiry <duration>] [--path <node-data>] [--api-endpoint <url>] [--peer-addr <ip:port>]\n  dioramactl token list [--path <node-data>] [--peer-addr <ip:port>]\n  dioramactl token invalidate <token-id> [--path <node-data>] [--peer-addr <ip:port>]\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenAction {
    Create {
        role: JoinRole,
        expiry_secs: Option<u64>,
    },
    List,
    Invalidate {
        token_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenOptions {
    pub action: TokenAction,
    pub path: PathBuf,
    pub api_endpoint: Option<String>,
    pub peer_addr: Option<SocketAddr>,
}

impl Default for TokenOptions {
    fn default() -> Self {
        Self {
            action: TokenAction::Create {
                role: JoinRole::Worker,
                expiry_secs: None,
            },
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
    let Some(subcmd) = args.first().map(String::as_str) else {
        return Err(crate::ParseError::UnknownCommand);
    };
    let mut options = TokenOptions::default();
    let mut role = JoinRole::Worker;
    let mut expiry_secs = None;
    let mut invalidate_id: Option<String> = None;

    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        if !arg.starts_with('-') && subcmd == "invalidate" && invalidate_id.is_none() {
            invalidate_id = Some(arg.clone());
            continue;
        }
        let (key, value) = match arg.split_once('=') {
            Some(pair) => pair,
            None => (
                arg.as_str(),
                rest.next().ok_or(crate::ParseError::UnknownFlag)?.as_str(),
            ),
        };
        match key {
            "--role" if subcmd == "create" => {
                role = value
                    .parse::<JoinRole>()
                    .map_err(|_| crate::ParseError::UnknownFlag)?;
            },
            "--expiry" if subcmd == "create" => {
                expiry_secs = parse_duration_secs(value)?;
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

    options.action = match subcmd {
        "create" => TokenAction::Create { role, expiry_secs },
        "list" => TokenAction::List,
        "invalidate" => TokenAction::Invalidate {
            token_id: invalidate_id.ok_or(crate::ParseError::UnknownFlag)?,
        },
        _ => return Err(crate::ParseError::UnknownCommand),
    };
    Ok(options)
}

fn parse_kubeconfig_server(
    kubeconfig: &str,
    default_peer: SocketAddr,
) -> Option<(String, SocketAddr, bool)> {
    for line in kubeconfig.lines() {
        let Some(server) = line.trim().strip_prefix("server:") else {
            continue;
        };
        let api = server.trim().trim_matches('"').to_string();
        if let Some(host_port) = api.strip_prefix("https://")
            && let Ok(sock) = host_port.parse::<SocketAddr>()
        {
            return Some((
                api,
                SocketAddr::new(sock.ip(), 2380),
                !sock.ip().is_loopback(),
            ));
        }
        return Some((api, default_peer, false));
    }
    None
}

fn discover_endpoints_from_pki(pki_dir: &Path) -> (String, SocketAddr) {
    let default_api = "https://127.0.0.1:6443".to_string();
    let default_peer: SocketAddr = "127.0.0.1:2380".parse().unwrap();
    let mut fallback: Option<(String, SocketAddr)> = None;

    for filename in [
        "kubelet.kubeconfig",
        "kube-controller-manager.kubeconfig",
        "admin.kubeconfig",
    ] {
        let Ok(kubeconfig) = std::fs::read_to_string(pki_dir.join(filename)) else {
            continue;
        };
        if let Some((api, peer, non_loopback)) = parse_kubeconfig_server(&kubeconfig, default_peer)
        {
            if non_loopback {
                return (api, peer);
            }
            if fallback.is_none() {
                fallback = Some((api, peer));
            }
        }
    }
    fallback.unwrap_or((default_api, default_peer))
}

fn open_token_datastore_client(
    data_dir: &Path,
    pki_dir: &Path,
    peer_addr: SocketAddr,
) -> Result<DatastoreClient, DatastoreError> {
    let ds_dir = data_dir.join("datastore");
    std::fs::create_dir_all(&ds_dir)?;
    match DatastoreEngine::open(DatastoreConfig::new(ds_dir)) {
        Ok((engine, _)) => Ok(engine.client()),
        Err(DatastoreError::LockContention(_)) => Ok(DatastoreClient::new_remote(
            peer_addr,
            Some(pki_dir.join("datastore-server.crt")),
            Some(pki_dir.join("datastore-server.key")),
        )),
        Err(err) => Err(err),
    }
}

fn run_token_future<F, T>(fut: F) -> io::Result<T>
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            Ok(rt.block_on(fut))
        })
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("token worker thread panicked")))
    })
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

    match &options.action {
        TokenAction::Create { role, expiry_secs } => execute_token_create(
            &options.path,
            &pki_dir,
            (*role, *expiry_secs, api_endpoint, peer_addr),
            stdout,
            stderr,
        ),
        TokenAction::List => execute_token_list(&options.path, &pki_dir, peer_addr, stdout, stderr),
        TokenAction::Invalidate { token_id } => {
            execute_token_invalidate(&options.path, &pki_dir, peer_addr, token_id, stdout, stderr)
        },
    }
}

fn execute_token_create(
    data_dir: &Path,
    pki_dir: &Path,
    params: (JoinRole, Option<u64>, String, SocketAddr),
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let (role, expiry_secs, api_endpoint, peer_addr) = params;
    let token =
        match JoinToken::create_from_pki_dir(pki_dir, role, api_endpoint, peer_addr, expiry_secs) {
            Ok(t) => t,
            Err(err) => {
                writeln!(stderr, "[fail] token create: {err}")?;
                return Ok(1);
            },
        };
    if let Ok(client) = open_token_datastore_client(data_dir, pki_dir, peer_addr) {
        let _ = run_token_future(client.register_bootstrap_token(&token));
    }
    match token.encode() {
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

fn execute_token_list(
    data_dir: &Path,
    pki_dir: &Path,
    peer_addr: SocketAddr,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let client = match open_token_datastore_client(data_dir, pki_dir, peer_addr) {
        Ok(c) => c,
        Err(err) => {
            writeln!(stderr, "[fail] token list: {err}")?;
            return Ok(1);
        },
    };
    match run_token_future(client.list_bootstrap_tokens())? {
        Ok(records) => {
            writeln!(stdout, "ID\tROLE\tEXPIRES AT")?;
            for rec in records {
                let exp = rec
                    .expires_at
                    .map_or_else(|| "never".to_string(), |v| v.to_string());
                writeln!(stdout, "{}\t{}\t{exp}", rec.token_id, rec.role)?;
            }
            Ok(0)
        },
        Err(err) => {
            writeln!(stderr, "[fail] token list: {err}")?;
            Ok(1)
        },
    }
}

fn execute_token_invalidate(
    data_dir: &Path,
    pki_dir: &Path,
    peer_addr: SocketAddr,
    token_id: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let client = match open_token_datastore_client(data_dir, pki_dir, peer_addr) {
        Ok(c) => c,
        Err(err) => {
            writeln!(stderr, "[fail] token invalidate: {err}")?;
            return Ok(1);
        },
    };
    match run_token_future(client.invalidate_bootstrap_token(token_id))? {
        Ok(_) => {
            writeln!(stdout, "token {token_id} invalidated")?;
            Ok(0)
        },
        Err(err) => {
            writeln!(stderr, "[fail] token invalidate: {err}")?;
            Ok(1)
        },
    }
}
