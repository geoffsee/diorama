mod common;
mod evidence;
mod oracle;
mod runtime;
use diorama_dev::Result;
pub(super) fn main() -> Result<u8> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "__exec") {
        return diorama_dev::process::child_exec(&args);
    }
    let args = args
        .into_iter()
        .map(|a| a.into_string().map_err(|_| "argument UTF8".into()))
        .collect::<Result<Vec<_>>>()?;
    let cancellation = diorama_dev::process::Cancellation::default();
    let _signals = if args.get(1).is_some_and(|s| s == "capture") {
        Some(diorama_dev::process::SignalGuard::install(
            cancellation.clone(),
        )?)
    } else {
        None
    };
    match args.as_slice() {
        [command, mode, directory] if command == "process-child" => {
            runtime::process(mode, directory.as_ref())
        },
        [command, mode, directory] if command == "output-child" => {
            runtime::output(mode, directory.as_ref())
        },
        [command, mode, directory] if command == "output-writer" => {
            runtime::writer(mode, directory.as_ref())
        },
        [command] if command == "namespace" => {
            namespace()?;
            Ok(0)
        },
        [family, command, directory] if command == "verify" => {
            evidence::verify(
                &diorama_dev::repository_root(&std::env::current_dir()?)?,
                family,
                directory.as_ref(),
                true,
            )?;
            Ok(0)
        },
        [family, command, directory, flag]
            if command == "verify" && flag == "--relevant-current" =>
        {
            evidence::verify(
                &diorama_dev::repository_root(&std::env::current_dir()?)?,
                family,
                directory.as_ref(),
                false,
            )?;
            Ok(0)
        },
        [family, command, directory] if command == "capture" => {
            evidence::capture(
                &diorama_dev::repository_root(&std::env::current_dir()?)?,
                family,
                directory.as_ref(),
                &cancellation,
            )?;
            Ok(0)
        },
        _ => Err("supervisor fixture command not recognized".into()),
    }
}
fn namespace() -> Result<()> {
    let stat = String::from_utf8(common::read(std::path::Path::new("/proc/self/stat"), 8192)?)?;
    let parent = stat
        .rsplit_once(") ")
        .ok_or("proc stat")?
        .1
        .split_whitespace()
        .nth(1)
        .ok_or("parent")?
        .parse::<u32>()?;
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        if let Some(pid) = entry?
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            pids.push(pid);
        }
        common::require(pids.len() <= 128, "namespace PID cap")?;
    }
    pids.sort_unstable();
    println!(
        "DIORAMA_NAMESPACE {}",
        serde_json::json!({"init":1,"shell":parent,"helper":std::process::id(),"processes":pids})
    );
    Ok(())
}
