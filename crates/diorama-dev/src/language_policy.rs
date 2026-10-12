//! Reject Python source, packaging and active interpreter calls in repository tooling.
use crate::{Result, read_bounded};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

pub fn violations(path: &Path, bytes: &[u8]) -> Result<Vec<String>> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let mut issues = Vec::new();
    if ["py", "pyi", "pyc", "pyo", "pyw", "pyz"].contains(&extension)
        || [
            "pyproject.toml",
            "uv.lock",
            "poetry.lock",
            "Pipfile",
            "Pipfile.lock",
            "setup.py",
            "setup.cfg",
        ]
        .contains(&name)
        || name.starts_with("requirements") && extension.eq_ignore_ascii_case("txt")
    {
        issues.push(format!("{}: Python source or packaging", path.display()));
    }
    // Raw historical captures/provenance are immutable evidence, never executed tooling.
    // Check the formats that contain active repository commands, not historical JSON/log data.
    if extension == "rs" {
        use syn::visit::Visit;
        struct Calls {
            found: bool,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                self.found |= interpreter_call(call);
                syn::visit::visit_expr_call(self, call);
            }
        }
        let syntax = syn::parse_file(std::str::from_utf8(bytes)?)?;
        let mut calls = Calls { found: false };
        calls.visit_file(&syntax);
        if calls.found {
            issues.push(format!("{}: Python interpreter invocation", path.display()));
        }
    }
    let executable_text = ["sh", "bash", "zsh", "yml", "yaml", "ps1", "cmd", "bat"]
        .contains(&extension)
        || name == "Dockerfile"
        || name.ends_with(".Dockerfile")
        || name == "Makefile"
        || name == "Justfile";
    if executable_text {
        let text = std::str::from_utf8(bytes)?;
        let interpreter = regex::Regex::new(
            r#"(?i)(?:^|[\s;|&"'])(?:exec\s+)?(?:[/\w.-]*/)?(?:python(?:[23](?:\.\d+)*)?|pypy[23]?)(?:[\s;"']|$)|#!/.*\b(?:python[23]?|pypy[23]?)\b"#,
        )?;
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if (trimmed.starts_with('#') && !trimmed.starts_with("#!")) || trimmed.starts_with("//")
            {
                continue;
            }
            if interpreter.is_match(line) {
                issues.push(format!(
                    "{}:{}: Python interpreter invocation",
                    path.display(),
                    index + 1
                ));
            }
        }
    }
    Ok(issues)
}

fn interpreter_call(call: &syn::ExprCall) -> bool {
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    let names = function
        .path
        .segments
        .iter()
        .map(|part| part.ident.to_string())
        .collect::<Vec<_>>();
    if !names.ends_with(&["Command".to_owned(), "new".to_owned()]) {
        return false;
    }
    let Some(syn::Expr::Lit(literal)) = call.args.first() else {
        return false;
    };
    let syn::Lit::Str(program) = &literal.lit else {
        return false;
    };
    let name = program.value();
    let name = Path::new(&name)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("");
    name.starts_with("python") || name.starts_with("pypy")
}

/// Include tracked files and untracked nonignored additions, while respecting staged deletions.
pub fn check(root: &Path) -> Result<Vec<String>> {
    let result = Command::new("git")
        .current_dir(root)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output()?;
    if !result.status.success() {
        return Err("cannot inventory repository files".into());
    }
    let mut issues = Vec::new();
    for raw in result
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let relative = PathBuf::from(std::str::from_utf8(raw)?);
        let path = root.join(&relative);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            // File names remain forbidden even when their targets are outside the tree.
            issues.extend(violations(&relative, b"")?);
            continue;
        }
        if metadata.is_file() {
            // Binary artifacts are not command text; policy names are still checked.
            let name = relative
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            let extension = relative
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            let text = [
                "rs", "sh", "bash", "zsh", "yml", "yaml", "ps1", "cmd", "bat",
            ]
            .contains(&extension)
                || name == "Dockerfile"
                || name.ends_with(".Dockerfile")
                || name == "Makefile"
                || name == "Justfile";
            let bytes = if text {
                read_bounded(&path, 8 * 1024 * 1024)?
            } else {
                Vec::new()
            };
            issues.extend(violations(&relative, &bytes)?);
        }
    }
    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_sources_packaging_inline_scripts_and_rust_shellouts() -> Result<()> {
        for name in [
            "driver.py",
            "types.pyi",
            "pyproject.toml",
            "uv.lock",
            "requirements-dev.txt",
        ] {
            assert!(!violations(Path::new(name), b"")?.is_empty(), "{name}");
        }
        for (name, source) in [
            ("ci.yml", "run: python3 tool.py"),
            ("Dockerfile", "RUN /usr/bin/python3 - <<'PY'"),
            ("script.sh", "#!/usr/bin/env python3"),
            ("script.sh", "exec pypy3 tool.py"),
            (
                "main.rs",
                r#"fn main() { let command = Command::new("python3"); }"#,
            ),
        ] {
            assert!(
                !violations(Path::new(name), source.as_bytes())?.is_empty(),
                "{source}"
            );
        }
        Ok(())
    }
    #[test]
    fn allows_rust_tools_and_immutable_historical_receipts() -> Result<()> {
        for (name, source) in [
            (
                "receipt.json",
                r#"{"capture_command":"python3 historical.py"}"#,
            ),
            ("build.log", "python3 historical.py"),
            ("ci.yml", "run: cargo test --locked"),
            ("script.sh", "# Historical tooling used python3."),
            ("main.rs", "// Python has been replaced."),
        ] {
            assert!(
                violations(Path::new(name), source.as_bytes())?.is_empty(),
                "{name}"
            );
        }
        Ok(())
    }
}
