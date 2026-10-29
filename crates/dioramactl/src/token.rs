//! Worker join credentials. These commands only read/write API credentials and Secrets.
use crate::ParseError;
use diorama_apiserver::{bootstrap::secret_field, transport::HttpsClient};
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
pub const HELP: &str = "dioramactl token create --role=worker --expiry=24h [--kubeconfig PATH]\ndioramactl token list [--kubeconfig PATH]\ndioramactl token invalidate ID [--kubeconfig PATH]\ndioramactl token export --token-file PATH\n";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenOptions {
    action: String,
    id: String,
    kubeconfig: PathBuf,
    file: PathBuf,
    expiry: u64,
}
pub fn parse(args: &[String]) -> Result<TokenOptions, ParseError> {
    let mut result = TokenOptions {
        action: args.first().ok_or(ParseError::UnknownCommand)?.clone(),
        id: String::new(),
        kubeconfig: "/var/lib/diorama/pki/admin.kubeconfig".into(),
        file: PathBuf::new(),
        expiry: 86400,
    };
    if !matches!(
        result.action.as_str(),
        "create" | "list" | "invalidate" | "export"
    ) {
        return Err(ParseError::UnknownCommand);
    }
    let mut args = args[1..].iter();
    while let Some(arg) = args.next() {
        if !arg.starts_with("--") && result.action == "invalidate" && result.id.is_empty() {
            result.id.clone_from(arg);
            continue;
        }
        let (key, value) = match arg.split_once('=') {
            Some(kv) => kv,
            None => (
                arg.as_str(),
                args.next().ok_or(ParseError::UnknownFlag)?.as_str(),
            ),
        };
        match key {
            "--role" if value == "worker" && result.action == "create" => {},
            "--expiry" if result.action == "create" => {
                result.expiry = duration(value).ok_or(ParseError::UnknownFlag)?;
            },
            "--kubeconfig" => result.kubeconfig = value.into(),
            "--token-file" if result.action == "export" => result.file = value.into(),
            _ => return Err(ParseError::UnknownFlag),
        }
    }
    if result.action == "invalidate"
        && (result.id.len() != 6 || !result.id.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return Err(ParseError::UnknownFlag);
    }
    if result.action == "export" && result.file.as_os_str().is_empty() {
        return Err(ParseError::UnknownFlag);
    }
    Ok(result)
}
fn duration(value: &str) -> Option<u64> {
    let (number, unit) = value.split_at_checked(value.len().checked_sub(1)?)?;
    let factor = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    number
        .parse::<u64>()
        .ok()?
        .checked_mul(factor)
        .filter(|s| *s > 0)
}
pub fn execute(options: &TokenOptions, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let result = if options.action == "export" {
        std::fs::read_to_string(&options.file)
            .and_then(|text| diorama_pki::base64_decode(text.trim()).map_err(io::Error::other))
            .and_then(|data| stdout.write_all(&data))
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .and_then(|runtime| {
                runtime
                    .block_on(run(options))
                    .and_then(|output| writeln!(stdout, "{output}"))
            })
    };
    if let Err(error) = result {
        let _ = writeln!(stderr, "token operation failed: {error}");
        1
    } else {
        0
    }
}
fn random_token() -> io::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut source = std::fs::File::open("/dev/urandom")?;
    let mut token = String::with_capacity(22);
    while token.len() < 22 {
        let mut random = [0u8; 32];
        source.read_exact(&mut random)?;
        for byte in random {
            // Rejection sampling preserves a uniform distribution over 36 symbols.
            if byte < 252 && token.len() < 22 {
                token.push(char::from(ALPHABET[usize::from(byte % 36)]));
            }
        }
    }
    Ok(token)
}
async fn run(options: &TokenOptions) -> io::Result<String> {
    let client = HttpsClient::new(&options.kubeconfig);
    let path = "/api/v1/namespaces/kube-system/secrets";
    match options.action.as_str() {
        "list" => {
            let list = client
                .request("GET", path, None)
                .await
                .map_err(io::Error::other)?;
            let entries: Vec<Value> = list["items"].as_array().into_iter().flatten().filter(|s| s["type"] == "bootstrap.kubernetes.io/token").map(|s| json!({"id":secret_field(s,"token-id"), "expiration":secret_field(s,"expiration")})).collect();
            serde_json::to_string_pretty(&entries).map_err(io::Error::other)
        },
        "invalidate" => {
            client
                .request(
                    "DELETE",
                    &format!("{path}/bootstrap-token-{}", options.id),
                    None,
                )
                .await
                .map_err(io::Error::other)?;
            Ok("invalidated".into())
        },
        "create" => {
            let token = random_token()?;
            let (id, secret) = token.split_at(6);
            let expiry = diorama_apiserver::time::now_unix()
                .checked_add(options.expiry)
                .ok_or_else(|| io::Error::other("expiry overflow"))?;
            let doc = json!({"apiVersion":"v1", "kind":"Secret", "metadata":{"name":format!("bootstrap-token-{id}"),"namespace":"kube-system"},"type":"bootstrap.kubernetes.io/token", "stringData":{"token-id":id,"token-secret":secret,"usage-bootstrap-authentication":"true","expiration":diorama_apiserver::time::rfc3339_seconds(expiry)}});
            client
                .request("POST", path, Some(doc))
                .await
                .map_err(io::Error::other)?;
            let config = client.document().map_err(io::Error::other)?;
            let current = config["contexts"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|c| c["name"] == config["current-context"])
                .ok_or_else(|| io::Error::other("missing current context"))?;
            let cluster = config["clusters"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|c| c["name"] == current["context"]["cluster"])
                .ok_or_else(|| io::Error::other("missing current cluster"))?;
            let mut cluster = cluster["cluster"].clone();
            if cluster.get("certificate-authority-data").is_none() {
                let path = cluster["certificate-authority"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("missing CA"))?;
                let ca = std::fs::read(
                    options
                        .kubeconfig
                        .parent()
                        .unwrap_or(std::path::Path::new("."))
                        .join(path),
                )?;
                cluster["certificate-authority-data"] = json!(diorama_pki::base64_encode(&ca));
            }
            cluster
                .as_object_mut()
                .unwrap()
                .remove("certificate-authority");
            let bootstrap = json!({"apiVersion":"v1","kind":"Config","clusters":[{"name":"diorama","cluster":cluster}],"users":[{"name":"bootstrap","user":{"token":format!("{id}.{secret}")}}],"contexts":[{"name":"bootstrap","context":{"cluster":"diorama","user":"bootstrap"}}],"current-context":"bootstrap"});
            Ok(diorama_pki::base64_encode(&serde_json::to_vec(&bootstrap)?))
        },
        _ => Err(io::Error::other("unknown token action")),
    }
}
