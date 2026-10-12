use super::common::{Result, array, check, fields, hex, json, read, strict};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, path::Path};
pub(super) const DECODE: [&str; 14] = [
    "aggregate_budget_is_checked_before_observer_and_retained_on_header_failure",
    "all_truncations_corrupt_checksum_and_trailing_members_fail_after_rehash",
    "empty_frames_still_require_completion_and_consume_one_probe",
    "exact_limit_succeeds_but_excess_and_failed_attempts_retain_budget_charges",
    "gzip_header_fields_are_bounded_before_decoder_allocation",
    "gzip_optional_fields_and_header_crc_are_checked_without_using_names_as_paths",
    "image_limit_and_executable_limit_are_distinct_and_receipt_requires_full_trailer",
    "independent_fixed_vectors_match_decoded_hash_and_binding",
    "invalid_limits_fail_without_a_session",
    "observer_failure_is_typed_provisional_and_display_does_not_leak",
    "same_encoded_slice_must_match_before_any_callback",
    "unknown_size_rle_bomb_is_streamed_in_fixed_chunks_and_stops_at_limit",
    "unknown_zstd_content_size_is_still_bounded_and_checksum_is_checked",
    "zstd_skippable_dictionary_large_window_and_reserved_headers_are_rejected",
];
pub(super) const ELF: [&str; 10] = [
    "altered_encoded_slice_fails_before_decode_and_keeps_attempt_charge",
    "every_supported_machine_preserves_header_only_abi_boundary",
    "exact_encoded_hash_does_not_hide_wrong_machine_class_endian_or_loader",
    "failed_elf_parsing_keeps_both_budgets_and_repeated_calls_exhaust_decoded_budget",
    "incomplete_or_corrupt_frames_never_reach_elf_inspection",
    "invalid_limits_identity_and_gzip_image_are_rejected_without_budget_effects",
    "raw_frame_and_independent_elf_share_completed_digest_and_observations",
    "retained_encoded_budget_cannot_be_refreshed_by_composition",
    "rle_expansion_stops_at_tighter_elf_cap_before_parser",
    "tighter_elf_decode_and_session_limits_bound_unknown_size_output",
];
pub(super) fn summary(raw: &str, count: usize) -> Result<()> {
    let rows: Vec<_> = raw
        .lines()
        .filter(|l| l.starts_with("test result:"))
        .collect();
    check(rows.len() == 1, "one test summary")?;
    let prefix = format!(
        "test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in "
    );
    let time = rows[0]
        .strip_prefix(&prefix)
        .and_then(|v| v.strip_suffix('s'))
        .ok_or("test completion")?;
    check(
        !time.is_empty() && time.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "test time",
    )
}
pub(super) fn runtime_binaries(lines: &[&str], names: &[&str]) -> Result<Value> {
    let mut out = Map::new();
    for (index, name) in names.iter().enumerate() {
        let line = lines.get(index).ok_or("binary line")?;
        let (sha, path) = line.split_once("  ").ok_or("binary delimiter")?;
        check(
            hex(sha, 64) && path == format!("/{name}"),
            "ordered runtime binary",
        )?;
        out.insert((*name).into(), sha.into());
    }
    check(
        lines
            .iter()
            .filter(|l| {
                l.split_once("  ")
                    .is_some_and(|(s, p)| hex(s, 64) && p.starts_with('/'))
            })
            .count()
            == names.len(),
        "exact binary count",
    )?;
    Ok(out.into())
}
pub(super) fn namespace(lines: &[&str]) -> Result<()> {
    let rows: Vec<_> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("DIORAMA_NAMESPACE "))
        .collect();
    check(
        rows.len() == 1
            && lines
                .last()
                .is_some_and(|l| l.starts_with("DIORAMA_NAMESPACE ")),
        "final namespace record",
    )?;
    let value = strict(rows[0].as_bytes())?;
    fields(&value, &["init", "shell", "helper", "processes"])?;
    let mut ids = Vec::new();
    for key in ["init", "shell", "helper"] {
        let id = value[key].as_u64().ok_or("namespace integer")?;
        check(id > 0 && u32::try_from(id).is_ok(), "positive bounded PID")?;
        ids.push(id);
    }
    check(
        ids[0] == 1 && ids.iter().collect::<BTreeSet<_>>().len() == 3,
        "namespace distinct identities",
    )?;
    ids.sort_unstable();
    let mut processes = array(&value["processes"])?
        .iter()
        .map(|v| v.as_u64().ok_or_else(|| "process integer".into()))
        .collect::<Result<Vec<_>>>()?;
    processes.sort_unstable();
    check(processes == ids, "namespace cleanup")
}
pub(super) fn records(path: &Path) -> Result<(Value, Value)> {
    let raw = String::from_utf8(read(path, 1024 * 1024)?)?;
    let lines: Vec<_> = raw.lines().collect();
    let binaries = runtime_binaries(&lines, &["decode-tests", "decoded_elf-tests", "fixture"])?;
    let mut out = Map::new();
    let mut cursor = 3;
    for (suite, expected) in [
        ("decode", DECODE.as_slice()),
        ("decoded_elf", ELF.as_slice()),
    ] {
        check(
            lines.get(cursor) == Some(&format!("DIORAMA_SUITE {suite}").as_str()),
            "suite order",
        )?;
        cursor += 1;
        let start = cursor;
        while cursor < lines.len()
            && !lines[cursor].starts_with("DIORAMA_SUITE ")
            && !lines[cursor].starts_with("DIORAMA_NAMESPACE ")
        {
            cursor += 1;
        }
        let text = lines[start..cursor].join("\n");
        summary(&text, expected.len())?;
        let mut names = Vec::new();
        for line in &lines[start..cursor] {
            if line.starts_with("test ") && !line.starts_with("test result:") {
                let name = line
                    .strip_prefix("test ")
                    .and_then(|v| v.strip_suffix(" ... ok"))
                    .ok_or("test failure")?;
                names.push(name);
            }
        }
        let mut wanted = expected.to_vec();
        wanted.sort_unstable();
        names.sort_unstable();
        check(names == wanted, "exact test inventory")?;
        out.insert(suite.into(), json!(names));
    }
    check(
        lines
            .iter()
            .filter(|line| line.starts_with("DIORAMA_"))
            .all(|line| line.starts_with("DIORAMA_SUITE ") || line.starts_with("DIORAMA_NAMESPACE ")),
        "unknown native record",
    )?;
    check(cursor + 1 == lines.len(), "native completion boundary")?;
    namespace(&lines)?;
    Ok((out.into(), binaries))
}
pub(super) fn builder(raw: &str, nonce: &str, names: &[&str]) -> Result<Value> {
    let mut normalized = Vec::new();
    for line in raw.lines() {
        let Some(rest) = line.strip_prefix('#') else {
            continue;
        };
        let mut tokens = rest.splitn(3, ' ');
        let step = tokens.next().unwrap_or("");
        let time = tokens.next().unwrap_or("");
        let body = tokens.next().unwrap_or("");
        if !step.is_empty()
            && step.bytes().all(|b| b.is_ascii_digit())
            && !time.is_empty()
            && time.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        {
            normalized.push(body);
        }
    }
    let begin = format!("DIORAMA_BUILD_BEGIN {nonce}");
    let end = format!("DIORAMA_BUILD_END {nonce}");
    let starts: Vec<_> = normalized
        .iter()
        .enumerate()
        .filter(|(_, v)| **v == begin)
        .map(|(i, _)| i)
        .collect();
    let ends: Vec<_> = normalized
        .iter()
        .enumerate()
        .filter(|(_, v)| **v == end)
        .map(|(i, _)| i)
        .collect();
    check(
        starts.len() == 1 && ends.len() == 1 && ends[0] > starts[0],
        "unique nonce frame",
    )?;
    let mut out = Map::new();
    let body = &normalized[starts[0] + 1..ends[0]];
    check(body.len() == names.len(), "builder binary count")?;
    for (line, name) in body.iter().zip(names) {
        let (sha, path) = line.split_once("  ").ok_or("builder hash")?;
        check(
            hex(sha, 64) && path == format!("/out/{name}"),
            "builder identity",
        )?;
        out.insert((*name).into(), sha.into());
    }
    Ok(out.into())
}
