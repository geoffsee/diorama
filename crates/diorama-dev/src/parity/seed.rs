//! Deterministic two-file ISO9660/Joliet `NoCloud` seed. No external image builder.
use super::{Result, require};
const BLOCK: usize = 2048;
fn both16(out: &mut [u8], value: u16) {
    out[..2].copy_from_slice(&value.to_le_bytes());
    out[2..4].copy_from_slice(&value.to_be_bytes());
}
fn both32(out: &mut [u8], value: u32) {
    out[..4].copy_from_slice(&value.to_le_bytes());
    out[4..8].copy_from_slice(&value.to_be_bytes());
}
fn record(extent: u32, size: u32, name: &[u8], directory: bool) -> Vec<u8> {
    let length = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
    let mut row = vec![0; length];
    row[0] = u8::try_from(length).expect("fixed short ISO name");
    both32(&mut row[2..10], extent);
    both32(&mut row[10..18], size);
    row[18..25].copy_from_slice(&[70, 1, 1, 0, 0, 0, 0]);
    row[25] = if directory { 2 } else { 0 };
    both16(&mut row[28..32], 1);
    row[32] = u8::try_from(name.len()).expect("fixed short ISO name");
    row[33..33 + name.len()].copy_from_slice(name);
    row
}
fn text(out: &mut [u8], value: &str, joliet: bool) {
    if joliet {
        for pair in out.chunks_exact_mut(2) {
            pair.copy_from_slice(&[0, b' ']);
        }
        for (pair, unit) in out.chunks_exact_mut(2).zip(value.encode_utf16()) {
            pair.copy_from_slice(&unit.to_be_bytes());
        }
    } else {
        out.fill(b' ');
        out[..value.len()].copy_from_slice(value.as_bytes());
    }
}
fn descriptor(kind: u8, total: u32, root: u32, little: u32, big: u32) -> Vec<u8> {
    let joliet = kind == 2;
    let mut block = vec![0; BLOCK];
    block[0] = kind;
    block[1..6].copy_from_slice(b"CD001");
    block[6] = 1;
    text(&mut block[8..40], "RUBIX", joliet);
    text(&mut block[40..72], "CIDATA", joliet);
    both32(&mut block[80..88], total);
    if joliet {
        block[88..91].copy_from_slice(b"%/E");
    }
    both16(&mut block[120..124], 1);
    both16(&mut block[124..128], 1);
    both16(&mut block[128..132], 2048);
    both32(&mut block[132..140], 10);
    block[140..144].copy_from_slice(&little.to_le_bytes());
    block[148..152].copy_from_slice(&big.to_be_bytes());
    block[156..190].copy_from_slice(&record(root, 2048, &[0], true));
    for start in [813, 830, 847, 864] {
        block[start..start + 17].copy_from_slice(b"1970010100000000\0");
    }
    block[881] = 1;
    block
}
/// The Joliet namespace exposes exactly `user-data` and `meta-data` on Linux.
pub(crate) fn image(user_data: &[u8], meta_data: &[u8]) -> Result<Vec<u8>> {
    require(
        user_data.len() <= 64 * 1024 && meta_data.len() <= 4096,
        "cloud seed payload bounds",
    )?;
    let user_sector = 25usize;
    let meta_sector = user_sector + user_data.len().div_ceil(BLOCK).max(1);
    let total = meta_sector + meta_data.len().div_ceil(BLOCK).max(1);
    let mut iso = vec![0; total * BLOCK];
    for (index, data) in [
        (16, descriptor(1, u32::try_from(total)?, 23, 19, 20)),
        (17, descriptor(2, u32::try_from(total)?, 24, 21, 22)),
    ] {
        iso[index * BLOCK..(index + 1) * BLOCK].copy_from_slice(&data);
    }
    iso[18 * BLOCK] = 255;
    iso[18 * BLOCK + 1..18 * BLOCK + 6].copy_from_slice(b"CD001");
    iso[18 * BLOCK + 6] = 1;
    for (sector, extent, big) in [
        (19, 23u32, false),
        (20, 23, true),
        (21, 24, false),
        (22, 24, true),
    ] {
        let row = &mut iso[sector * BLOCK..sector * BLOCK + 10];
        row[0] = 1;
        row[2..6].copy_from_slice(&if big {
            extent.to_be_bytes()
        } else {
            extent.to_le_bytes()
        });
        row[6..8].copy_from_slice(&if big {
            1u16.to_be_bytes()
        } else {
            1u16.to_le_bytes()
        });
    }
    for (sector, joliet) in [(23, false), (24, true)] {
        let mut directory = record(u32::try_from(sector)?, 2048, &[0], true);
        directory.extend(record(u32::try_from(sector)?, 2048, &[1], true));
        for (ascii, name, extent, size) in [
            ("USERDATA.;1", "user-data;1", user_sector, user_data.len()),
            ("METADATA.;1", "meta-data;1", meta_sector, meta_data.len()),
        ] {
            let encoded = if joliet {
                name.encode_utf16()
                    .flat_map(u16::to_be_bytes)
                    .collect::<Vec<_>>()
            } else {
                ascii.as_bytes().to_vec()
            };
            directory.extend(record(
                u32::try_from(extent)?,
                u32::try_from(size)?,
                &encoded,
                false,
            ));
        }
        iso[sector * BLOCK..sector * BLOCK + directory.len()].copy_from_slice(&directory);
    }
    iso[user_sector * BLOCK..user_sector * BLOCK + user_data.len()].copy_from_slice(user_data);
    iso[meta_sector * BLOCK..meta_sector * BLOCK + meta_data.len()].copy_from_slice(meta_data);
    Ok(iso)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Independent consumer: discover the supplementary descriptor, traverse its
    // directory bytes and decode names/extents instead of assuming writer offsets.
    fn consume(iso: &[u8]) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        let descriptor = iso
            .chunks_exact(2048)
            .skip(16)
            .find(|b| b[0] == 2 && &b[1..6] == b"CD001")
            .ok_or("missing Joliet")?;
        require(&descriptor[88..91] == b"%/E", "Joliet escape sequence")?;
        let volume: String = descriptor[40..72]
            .chunks_exact(2)
            .map(|b| char::from_u32(u32::from(u16::from_be_bytes([b[0], b[1]]))).unwrap())
            .collect();
        require(volume.trim() == "CIDATA", "NoCloud label")?;
        let root = u32::from_le_bytes(descriptor[158..162].try_into()?);
        let size = u32::from_le_bytes(descriptor[166..170].try_into()?);
        let data = &iso[root as usize * 2048..root as usize * 2048 + size as usize];
        let mut offset = 0;
        let mut result = std::collections::BTreeMap::new();
        while data[offset] != 0 {
            let row = &data[offset..offset + usize::from(data[offset])];
            let name = &row[33..33 + usize::from(row[32])];
            if row[25] & 2 == 0 {
                let units = name
                    .chunks_exact(2)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>();
                let name = String::from_utf16(&units)?
                    .trim_end_matches(";1")
                    .to_owned();
                let extent = u32::from_le_bytes(row[2..6].try_into()?) as usize;
                let length = u32::from_le_bytes(row[10..14].try_into()?) as usize;
                require(
                    u32::from_be_bytes(row[6..10].try_into()?) as usize == extent,
                    "extent endian agreement",
                )?;
                result.insert(name, iso[extent * 2048..extent * 2048 + length].to_vec());
            }
            offset += row.len();
        }
        Ok(result)
    }
    #[test]
    fn nocloud_exact_names_label_and_multisector_payload() -> Result<()> {
        let user = format!("#cloud-config\n{}", "x".repeat(5000));
        let meta = "instance-id: diorama-owned\nlocal-hostname: diorama-parity\n";
        let iso = image(user.as_bytes(), meta.as_bytes())?;
        let files = consume(&iso)?;
        assert_eq!(files.len(), 2);
        assert_eq!(files["user-data"], user.as_bytes());
        assert_eq!(files["meta-data"], meta.as_bytes());
        assert_eq!(iso, image(user.as_bytes(), meta.as_bytes())?);
        Ok(())
    }
    #[test]
    fn seed_bounds_and_corrupted_consumer_fail() -> Result<()> {
        assert!(image(&vec![0; 65537], b"").is_err());
        let mut iso = image(b"#cloud-config\n", b"instance-id: x\n")?;
        iso[17 * 2048 + 88] = 0;
        assert!(consume(&iso).is_err());
        Ok(())
    }
}
