#![allow(unused)]

//! Explicit read-only qualification; downloaded artifacts are never executed.
#[allow(clippy::duplicate_mod)]
#[path = "common/elf.rs"]
mod common;
use diorama_assets::{AssetId, ElfLimits};
use diorama_platform::{Architecture, Libc};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::{fs::File, io::Read, path::PathBuf};
#[cfg(any())]
#[test]
#[ignore = "requires explicitly prepared checksum-locked API/Kine files"]
fn four_locked_release_executables() {
    let directory = PathBuf::from(
        std::env::var_os("diorama_ELF_FIXTURES").expect("explicit fixture directory"),
    );
    let pins: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../experiments/component-boundary/inputs.json"
    ))
    .unwrap();
    for (name, architecture) in [
        ("arm64", Architecture::Arm64),
        ("amd64", Architecture::Amd64),
    ] {
        for role in ["kube-apiserver", "kine"] {
            let mut bytes = Vec::new();
            File::open(directory.join(format!("{role}-{name}")))
                .unwrap()
                .take(256 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .unwrap();
            let hash = Sha256::digest(&bytes)
                .iter()
                .fold(String::new(), |mut s, v| {
                    write!(&mut s, "{v:02x}").unwrap();
                    s
                });
            assert_eq!(
                hash,
                pins["artifacts"][name][role]["sha256"].as_str().unwrap()
            );
            let result = common::inventory(&bytes, architecture, Libc::Glibc)
                .inspect_identity_elf(
                    if role == "kine" {
                        AssetId::Kine
                    } else {
                        AssetId::KubeApiserver
                    },
                    &bytes,
                    ElfLimits::default(),
                )
                .unwrap();
            println!(
                "diorama_ELF {}",
                json!({"sha256":hash,"role":role,"architecture":name,"bytes":bytes.len(),"machine":result.machine(),"elf_type":result.elf_type(),"entry":result.entry(),"flags":result.flags(),"interpreter":result.interpreter().map(|s|String::from_utf8(s.to_vec()).unwrap()),"needed":result.needed().iter().map(|s|String::from_utf8(s.clone()).unwrap()).collect::<Vec<_>>(),"loader":format!("{:?}",result.loader_family()),"loader_relation":format!("{:?}",result.loader_relation())})
            );
        }
    }
}
