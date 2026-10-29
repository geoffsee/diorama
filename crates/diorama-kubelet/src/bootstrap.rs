//! Worker-side bootstrap and renewal. The only private key written here belongs
//! to this kubelet; CA keys are never read or transported.
use crate::{KubeletConfigOptions, KubeletError};
use diorama_apiserver::transport::HttpsClient;
use serde_json::{Value, json};
use std::path::Path;

fn error(reason: impl Into<String>) -> KubeletError {
    KubeletError::AuthenticationFailed {
        reason: reason.into(),
    }
}
fn renewal_due(path: &Path) -> bool {
    let Ok(pem) = std::fs::read(path) else {
        return true;
    };
    let Ok((_, pem)) = diorama_pki::x509_parser::pem::parse_x509_pem(&pem) else {
        return true;
    };
    let Ok((_, cert)) = diorama_pki::x509_parser::parse_x509_certificate(&pem.contents) else {
        return true;
    };
    let now = i64::try_from(diorama_apiserver::time::now_unix()).unwrap_or(i64::MAX);
    let lifetime = cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
    now >= cert.validity().not_before.timestamp() + lifetime * 7 / 10
}

pub(crate) async fn ensure(options: &KubeletConfigOptions) -> Result<(), KubeletError> {
    if options.kubeconfig.exists() && !renewal_due(&options.cert_file) {
        return Ok(());
    }
    let bootstrap_path = options.root_dir.join("bootstrap.kubeconfig");
    let joining = !options.kubeconfig.exists();
    if joining {
        let file = options
            .bootstrap_token_file
            .as_ref()
            .ok_or_else(|| error("worker requires token-file"))?;
        let encoded = std::fs::read_to_string(file).map_err(|_| error("cannot read token-file"))?;
        let decoded = diorama_pki::base64_decode(encoded.trim())
            .map_err(|_| error("invalid encoded bootstrap kubeconfig"))?;
        diorama_pki::atomic_write(&bootstrap_path, &decoded, 0o600)
            .map_err(|_| error("cannot install bootstrap kubeconfig"))?;
    }
    let client = HttpsClient::new(if joining {
        &bootstrap_path
    } else {
        &options.kubeconfig
    });
    let document = client.document().map_err(|_| error("invalid kubeconfig"))?;
    let context = document["contexts"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|context| context["name"] == document["current-context"])
        .ok_or_else(|| error("missing current context"))?;
    let cluster = &document["clusters"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|cluster| cluster["name"] == context["context"]["cluster"])
        .ok_or_else(|| error("missing current cluster"))?["cluster"];
    let endpoint = cluster["server"]
        .as_str()
        .ok_or_else(|| error("missing API endpoint"))?;
    let ca = cluster["certificate-authority-data"]
        .as_str()
        .ok_or_else(|| error("missing bootstrap CA"))?;
    let ca_pem = diorama_pki::base64_decode(ca).map_err(|_| error("invalid bootstrap CA"))?;
    diorama_pki::atomic_write(&options.ca_file, &ca_pem, 0o644)
        .map_err(|_| error("cannot install CA"))?;
    let request = diorama_pki::bootstrap::kubelet_request(&options.node_name, &options.key_file)
        .map_err(|_| error("cannot generate node CSR"))?;
    let doc = json!({"apiVersion":"certificates.k8s.io/v1", "kind":"CertificateSigningRequest", "metadata":{"generateName":"node-client-"},"spec":{"request":diorama_pki::base64_encode(request.as_bytes()),"signerName":diorama_pki::bootstrap::KUBELET_SIGNER,"expirationSeconds":86400,"usages":["digital signature","key encipherment","client auth"]}});
    let path = "/apis/certificates.k8s.io/v1/certificatesigningrequests";
    let created = client
        .request("POST", path, Some(doc))
        .await
        .map_err(|e| error(e.to_string()))?;
    let name = created
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or_else(|| error("CSR response missing name"))?;
    for _ in 0..120 {
        let csr = client
            .request("GET", &format!("{path}/{name}"), None)
            .await
            .map_err(|e| error(e.to_string()))?;
        if let Some(certificate) = csr
            .pointer("/status/certificate")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
        {
            let cert = diorama_pki::base64_decode(certificate)
                .map_err(|_| error("invalid signed certificate"))?;
            let pem = std::str::from_utf8(&cert).map_err(|_| error("invalid certificate PEM"))?;
            let ca_text = std::str::from_utf8(&ca_pem).map_err(|_| error("invalid CA PEM"))?;
            let identity = diorama_pki::verify_certificate_chain(pem, ca_text)
                .map_err(|_| error("signed certificate failed validation"))?;
            if identity.common_name != format!("system:node:{}", options.node_name) {
                return Err(error("signed identity differs from node identity"));
            }
            diorama_pki::atomic_write(&options.cert_file, &cert, 0o600)
                .map_err(|_| error("cannot install signed certificate"))?;
            let key =
                std::fs::read(&options.key_file).map_err(|_| error("cannot read local key"))?;
            diorama_pki::kubeconfig::write_kubeconfig(
                &options.kubeconfig,
                endpoint,
                "diorama",
                &format!("system:node:{}", options.node_name),
                ca,
                certificate,
                &diorama_pki::base64_encode(&key),
            )
            .map_err(|_| error("cannot install node kubeconfig"))?;
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(error("timed out waiting for kubelet client certificate"))
}
