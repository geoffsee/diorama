//! Independent, source-specified distribution fixture expectations.
//!
//! These constructors preserve the reviewed Go behavior, including characterized
//! weaknesses. Captured output is never used to construct the expected result.
use std::path::Path;

use crate::{Result, json, read_bounded};
use serde_json::Value;

pub mod config_api;
pub mod config_links;
pub mod credentials;
pub mod mapping;
pub mod node_config;
pub mod pki;
pub mod policy;
pub mod resources;
pub mod webhook;

pub const LIMIT: u64 = 1024 * 1024;

pub fn load(path: &Path) -> Result<Value> {
    json::parse(&read_bounded(path, LIMIT)?)
}

pub fn equal(actual: &Value, expected: &Value) -> Result<()> {
    let changes = json::changes(expected, actual);
    if changes.is_empty() {
        Ok(())
    } else {
        Err(format!("fixture differs: {}", serde_json::to_string(&changes)?).into())
    }
}

/// Exactly one strict record must occur in each bounded execution log.
pub fn record(path: &Path) -> Result<Value> {
    let bytes = read_bounded(path, LIMIT)?;
    let text = std::str::from_utf8(&bytes)?;
    let mut records = text
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_CAPTURE "));
    let first = records.next().ok_or("capture record missing")?;
    if records.next().is_some() {
        return Err("duplicate capture record".into());
    }
    json::parse(first.as_bytes())
}

pub fn verify_repeats(directory: &Path, component: &str, expected: &Value) -> Result<()> {
    let actual = load(&directory.join(format!("{component}.json")))?;
    equal(&actual, expected)?;
    for index in 0..2 {
        equal(
            &record(&directory.join(format!("{component}-{index}.log")))?,
            expected,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
