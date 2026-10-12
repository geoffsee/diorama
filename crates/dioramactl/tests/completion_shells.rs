use dioramactl::{Shell, generate_completion};
use std::process::Command;

#[test]
fn powershell_completes_commands_and_shell_arguments() {
    let executable = std::env::var_os("diorama_REVIEW_PWSH").unwrap_or_else(|| "pwsh".into());
    let mut script = Vec::new();
    generate_completion(Shell::PowerShell, &mut script).unwrap();
    let script = String::from_utf8(script).unwrap();
    let binary_dir = std::path::Path::new(env!("CARGO_BIN_EXE_dioramactl"))
        .parent()
        .unwrap();
    let search_path = std::env::join_paths(std::iter::once(binary_dir.to_owned()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))
    .unwrap();
    for (input, expected) in [
        ("dioramactl co", vec!["completion", "config"]),
        ("dioramactl completion", vec!["completion"]),
        (
            "dioramactl completion ",
            vec!["bash", "fish", "powershell", "zsh"],
        ),
        ("dioramactl completion p", vec!["powershell"]),
        ("dioramactl completion zs", vec!["zsh"]),
    ] {
        // Passing the complete script avoids stdin's interactive line-reader,
        // which emits terminal mode escapes on Linux even with redirected output.
        let invocation = format!(
            "{script}\n[System.Management.Automation.CommandCompletion]::CompleteInput('{input}', {}, $null).CompletionMatches | ForEach-Object {{ $_.CompletionText }}",
            input.len(),
        );
        let output = match Command::new(&executable)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
            .arg(invocation)
            .env("PATH", &search_path)
            .env("TERM", "xterm-256color")
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("PowerShell is unavailable; native completion smoke test skipped");
                return;
            },
            Err(error) => panic!("cannot run PowerShell: {error}"),
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut matches = stdout.lines().collect::<Vec<_>>();
        matches.sort_unstable();
        assert_eq!(matches, expected, "completion for {input:?}");
    }
}
