// Shared independent vectors: the real-artifact test uses only inventory construction.
#![allow(dead_code)]
use diorama_assets::{
    AssetId, DeclaredInventory, ElfError, ElfLimits, InventoryRequest, Limits, Manifest, Scope,
    Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write;
pub(crate) fn put(b: &mut [u8], offset: usize, value: u64, width: usize) {
    b[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
// Independent System V ELF layout, not the object writer/parser under test.
pub(crate) fn executable(machine: u16, class: u8) -> Vec<u8> {
    let mut b = vec![0; 512];
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', class, 1, 1]);
    put(&mut b, 16, 2, 2);
    put(&mut b, 18, u64::from(machine), 2);
    put(&mut b, 20, 1, 4);
    if class == 2 {
        for (o, v, w) in [
            (24, 0x40_0100, 8),
            (32, 64, 8),
            (52, 64, 2),
            (54, 56, 2),
            (56, 1, 2),
            (58, 64, 2),
            (64, 1, 4),
            (68, 5, 4),
            (80, 0x40_0000, 8),
            (96, 512, 8),
            (104, 512, 8),
            (112, 4096, 8),
        ] {
            put(&mut b, o, v, w);
        }
    } else {
        for (o, v, w) in [
            (24, 0x10100, 4),
            (28, 52, 4),
            (40, 52, 2),
            (42, 32, 2),
            (44, 1, 2),
            (46, 40, 2),
            (52, 1, 4),
            (60, 0x10000, 4),
            (68, 512, 4),
            (72, 512, 4),
            (76, 5, 4),
            (80, 4096, 4),
        ] {
            put(&mut b, o, v, w);
        }
    }
    b
}
pub(crate) fn inventory(b: &[u8], architecture: Architecture, libc: Libc) -> DeclaredInventory {
    let mut v: Value =
        serde_json::from_slice(include_bytes!("../fixtures/online-amd64.json")).unwrap();
    v["target"]["architecture"] = json!(match architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
        Architecture::ArmV7 => "armv7",
        Architecture::Riscv64 => "riscv64",
    });
    v["target"]["libc"] = json!(if libc == Libc::Musl { "musl" } else { "glibc" });
    for a in v["assets"].as_array_mut().unwrap() {
        if a["id"] == "kube-apiserver" || a["id"] == "kine" {
            a["delivery"]["encoded_bytes"] = json!(b.len());
            a["delivery"]["sha256"] =
                json!(Sha256::digest(b).iter().fold(String::new(), |mut s, v| {
                    write!(&mut s, "{v:02x}").unwrap();
                    s
                }));
        }
        if (a["id"] == "image-d2k"
            && matches!(architecture, Architecture::ArmV7 | Architecture::Riscv64))
            || (a["id"] == "image-portainer-agent" && architecture == Architecture::Riscv64)
        {
            a["delivery"] = json!({"kind":"unavailable"});
        }
    }
    Manifest::decode(&serde_json::to_vec(&v).unwrap(), Limits::default())
        .unwrap()
        .validate_inventory(
            InventoryRequest {
                target: NodeTarget { architecture, libc },
                variant: Variant::Online,
                scope: Scope::SupervisedBundle,
            },
            Limits::default(),
        )
        .unwrap()
}
pub(crate) fn inspect(b: &[u8]) -> Result<diorama_assets::ElfInspection, ElfError> {
    inventory(b, Architecture::Amd64, Libc::Glibc).inspect_identity_elf(
        AssetId::KubeApiserver,
        b,
        ElfLimits::default(),
    )
}
