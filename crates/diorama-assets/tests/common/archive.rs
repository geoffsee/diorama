// Independent USTAR and RFC1952 stored-DEFLATE construction. No tar/compression writer under test.
#![allow(dead_code)]
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write;
pub(crate) fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            write!(&mut s, "{b:02x}").unwrap();
            s
        })
}
pub(crate) fn config(architecture: &str, variant: Option<&str>, refs: usize) -> Vec<u8> {
    let mut value = json!({"os":"linux","architecture":architecture,"rootfs":{"type":"layers","diff_ids":vec![format!("sha256:{}","11".repeat(32));refs]},"extension":{"nested":[null,true,1.5]}});
    if let Some(variant) = variant {
        value["variant"] = json!(variant);
    }
    serde_json::to_vec(&value).unwrap()
}
pub(crate) fn manifest(config: &[u8], layers: &[&[u8]]) -> Vec<u8> {
    serde_json::to_vec(&json!([{"Config":format!("sha256:{}",hex(config)),"RepoTags":["example.invalid/image:fixture"],"Layers":layers.iter().map(|b|format!("{}.tar.gz",hex(b))).collect::<Vec<_>>()}])).unwrap()
}
pub(crate) fn checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let value: u64 = header.iter().map(|b| u64::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{value:06o}\0 ").as_bytes());
}
pub(crate) fn entry(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 512];
    out[..name.len()].copy_from_slice(name.as_bytes());
    out[100..108].copy_from_slice(b"0000644\0");
    out[108..116].copy_from_slice(b"0000000\0");
    out[116..124].copy_from_slice(b"0000000\0");
    out[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
    out[136..148].copy_from_slice(b"00000000000\0");
    out[156] = b'0';
    out[257..265].copy_from_slice(b"ustar\x0000");
    checksum(&mut out);
    out.extend_from_slice(bytes);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}
pub(crate) fn archive(config: &[u8], layers: &[&[u8]], manifest: &[u8]) -> Vec<u8> {
    let mut out = entry(&format!("sha256:{}", hex(config)), config);
    let mut seen = std::collections::BTreeSet::new();
    for layer in layers {
        let name = format!("{}.tar.gz", hex(layer));
        if seen.insert(name.clone()) {
            out.extend(entry(&name, layer));
        }
    }
    out.extend(entry("manifest.json", manifest));
    out.extend([0; 1024]);
    out
}
pub(crate) fn standard() -> Vec<u8> {
    let c = config("amd64", None, 1);
    let layers = [&b"abc"[..]];
    archive(&c, &layers, &manifest(&c, &layers))
}
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320u32.wrapping_mul(crc & 1));
        }
    }
    !crc
}
pub(crate) fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    let count = bytes.len().div_ceil(65535);
    for (i, chunk) in bytes.chunks(65535).enumerate() {
        out.push(u8::from(i + 1 == count));
        let len = u16::try_from(chunk.len()).unwrap();
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend(crc32(bytes).to_le_bytes());
    out.extend(u32::try_from(bytes.len()).unwrap().to_le_bytes());
    out
}
