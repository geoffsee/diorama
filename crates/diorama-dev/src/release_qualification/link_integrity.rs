//! Documentation link integrity and completeness verification.
//!
//! Enforces:
//! - Verification of relative markdown links across all documentation artifacts.
//! - Detection of broken references or nonexistent target files.
//! - Completeness audit ensuring authoritative architectural documents exist and are populated.

use crate::Result;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

/// Summary of link integrity verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkIntegritySummary {
    pub documents_checked: usize,
    pub total_links: usize,
    pub local_links_verified: usize,
    pub external_links_skipped: usize,
    pub broken_links: Vec<BrokenLink>,
}

/// A broken link discovered in documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokenLink {
    pub source_file: PathBuf,
    pub line_number: usize,
    pub link_text: String,
    pub target: String,
    pub resolved_path: PathBuf,
}

impl std::fmt::Display for BrokenLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: broken link '[{}]({})' -> {}",
            self.source_file.display(),
            self.line_number,
            self.link_text,
            self.target,
            self.resolved_path.display()
        )
    }
}

/// Core architectural documents that must be present and non-empty.
pub const REQUIRED_DOCUMENTS: &[&str] = &[
    "README.md",
    "docs/architecture/acceptance-matrix.md",
    "docs/architecture/compatibility-contract.md",
    "docs/architecture/upstream-inputs.md",
    "docs/architecture/upstream-inputs.json",
    "docs/architecture/state-transitions.md",
    "docs/architecture/recovery-lifecycle-qualification.md",
    "docs/architecture/attribution.md",
    "docs/internal/development-status.md",
    "experiments/component-boundary/ADR.md",
];

/// Collect all markdown files in `docs/` and root `README.md`.
pub fn discover_markdown_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    let readme = root.join("README.md");
    if readme.is_file() {
        files.push(readme);
    }

    let docs_dir = root.join("docs");
    if docs_dir.is_dir() {
        walk_dir(&docs_dir, &mut files)?;
    }

    files.sort();
    Ok(files)
}

fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            walk_dir(&path, files)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "md") {
            files.push(path);
        }
    }
    Ok(())
}

/// Verifies that all required documentation files exist and are non-empty.
pub fn verify_required_documents_exist(root: &Path) -> Result<usize> {
    for rel_path in REQUIRED_DOCUMENTS {
        let full_path = root.join(rel_path);
        if !full_path.is_file() {
            return Err(format!("missing required document: {}", full_path.display()).into());
        }
        let meta = fs::metadata(&full_path)
            .map_err(|e| format!("cannot read metadata for {}: {e}", full_path.display()))?;
        if meta.len() == 0 {
            return Err(format!("required document is empty: {}", full_path.display()).into());
        }
    }
    Ok(REQUIRED_DOCUMENTS.len())
}

/// Verifies all links across discovered documentation files.
pub fn verify_documentation_links(root: &Path) -> Result<LinkIntegritySummary> {
    verify_required_documents_exist(root)?;

    let doc_files = discover_markdown_files(root)?;
    let mut summary = LinkIntegritySummary {
        documents_checked: doc_files.len(),
        ..Default::default()
    };

    // Regex for inline markdown links: [text](target)
    let inline_re = Regex::new(r"\[([^\]]+)\]\(([^)]+)\)")
        .map_err(|e| format!("regex compilation failed: {e}"))?;

    for file in &doc_files {
        let content = fs::read_to_string(file)
            .map_err(|e| format!("failed to read file {}: {e}", file.display()))?;

        let parent_dir = file.parent().unwrap_or(root);

        for (line_idx, line) in content.lines().enumerate() {
            for cap in inline_re.captures_iter(line) {
                summary.total_links += 1;
                let link_text = cap.get(1).map_or("", |m| m.as_str());
                let target = cap.get(2).map_or("", |m| m.as_str()).trim();

                // Skip external URLs
                if target.starts_with("http://")
                    || target.starts_with("https://")
                    || target.starts_with("mailto:")
                {
                    summary.external_links_skipped += 1;
                    continue;
                }

                // Strip target title if present (e.g. `path "title"`)
                let target_path_str = target.split_whitespace().next().unwrap_or(target);

                // Strip hash anchor
                let path_without_anchor = match target_path_str.split_once('#') {
                    Some((prefix, _)) => prefix,
                    None => target_path_str,
                };

                // Same-page anchor `#foo`
                if path_without_anchor.is_empty() {
                    summary.local_links_verified += 1;
                    continue;
                }

                let resolved = normalize_path(&parent_dir.join(path_without_anchor));
                if resolved.exists() {
                    summary.local_links_verified += 1;
                } else {
                    summary.broken_links.push(BrokenLink {
                        source_file: file.clone(),
                        line_number: line_idx + 1,
                        link_text: link_text.to_string(),
                        target: target.to_string(),
                        resolved_path: resolved,
                    });
                }
            }
        }
    }

    if !summary.broken_links.is_empty() {
        use std::fmt::Write as _;
        let mut msg = format!(
            "found {} broken documentation links:\n",
            summary.broken_links.len()
        );
        for broken in &summary.broken_links {
            let _ = writeln!(msg, "  - {broken}");
        }
        return Err(msg.into());
    }

    Ok(summary)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(c) => components.push(c),
            std::path::Component::ParentDir => {
                components.pop();
            },
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                components.clear();
            },
            std::path::Component::CurDir => {},
        }
    }

    let mut out = PathBuf::from("/");
    for c in components {
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_documents_check() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let count = verify_required_documents_exist(root)?;
        assert_eq!(count, REQUIRED_DOCUMENTS.len());
        Ok(())
    }

    #[test]
    fn test_documentation_links_integrity() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let summary = verify_documentation_links(root)?;
        assert!(summary.documents_checked > 0);
        assert!(summary.local_links_verified > 0);
        assert!(summary.broken_links.is_empty());
        Ok(())
    }
}
