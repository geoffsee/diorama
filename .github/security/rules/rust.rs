// Parser fixtures for Semgrep, not compiled workspace source.
fn tls(client: Client) {
    // ruleid: diorama-invalid-tls-certificates
    client.danger_accept_invalid_certs(true);
    // ok: diorama-invalid-tls-certificates
    client.danger_accept_invalid_certs(false);
    // ruleid: diorama-invalid-tls-hostnames
    client.danger_accept_invalid_hostnames(true);
    // ok: diorama-invalid-tls-hostnames
    client.danger_accept_invalid_hostnames(false);
    // ruleid: diorama-native-tls-verification
    client.set_verify(openssl::ssl::SslVerifyMode::NONE);
    // ok: diorama-native-tls-verification
    client.set_verify(openssl::ssl::SslVerifyMode::PEER);
    // ruleid: diorama-native-tls-verification
    client.ssl_verify_peer(false);
    // ruleid: diorama-native-tls-verification
    client.ssl_verify_host(false);
    // ok: diorama-native-tls-verification
    client.ssl_verify_peer(true);
    // ok: diorama-native-tls-verification
    client.ssl_verify_host(true);
}

fn hashes(data: &[u8]) {
    // ruleid: diorama-weak-hash
    let _ = md5::compute(data);
    // ruleid: diorama-weak-hash
    let _ = md5::Md5::new();
    // ruleid: diorama-weak-hash
    let _ = sha1::Sha1::new();
    // ruleid: diorama-weak-hash
    let _ = sha1::Sha1::digest(data);
    // ok: diorama-weak-hash
    let _ = sha2::Sha256::digest(data);
}

fn commands(input: &str) {
    // ruleid: diorama-formatted-shell-command
    std::process::Command::new("sh").arg("-c").arg(format!("echo {}", input));
    // ruleid: diorama-formatted-shell-command
    std::process::Command::new("/bin/bash").arg("-c").arg(format!("echo {}", input));
    // ok: diorama-formatted-shell-command
    std::process::Command::new("echo").arg(input);
    // ok: diorama-formatted-shell-command
    std::process::Command::new("sh").arg("-c").arg("echo fixed");
}
