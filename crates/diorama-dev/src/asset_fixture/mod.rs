mod archive;
mod capture;
mod common;
mod elf;
mod layer;
mod layer_oracle;
mod manifest;
mod manifest_oracle;
mod native;
#[cfg(test)]
mod tests;
use common::{Result, root};
pub(super) fn main() -> Result<()> {
    let args_os = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args_os.first().is_some_and(|argument| argument == "__exec") {
        diorama_dev::process::child_exec(&args_os)?;
        return Ok(());
    }
    let args = args_os
        .into_iter()
        .map(|argument| argument.into_string().map_err(|_| "argument UTF8".into()))
        .collect::<Result<Vec<_>>>()?;
    let _signals = if args.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "capture" | "archive-runtime" | "layer-runtime" | "manifest-runtime"
        )
    }) {
        Some(diorama_dev::process::SignalGuard::install(
            common::cancellation(),
        )?)
    } else {
        None
    };

    match args.as_slice() {
        [command] if command == "namespace" => capture::namespace(),
        [command] if command == "archive-runtime" => archive::runtime(),
        [command] if command == "layer-runtime" => layer::runtime(),
        [command] if command == "manifest-runtime" => manifest::runtime(),
        [command, cache] if command == "manifest-inputs" => manifest_oracle::verify_inputs(cache.as_ref()).map(|_| ()),
        [command, actual, pinned] if command == "manifest-graph" => archive::graph_module(actual.as_ref(), pinned.as_ref(), "diorama.invalid/assets-manifest-fixture"),
        [family, command, directory, cache] if family == "manifest" && command == "capture" => capture::docker_cached(&root()?, family, directory.as_ref(), Some(cache.as_ref())),
        [command, actual, pinned] if command == "layer-graph" => archive::graph_module(actual.as_ref(), pinned.as_ref(), "diorama.invalid/assets-layer-fixture"),
        [command, actual, pinned] if command == "graph" => archive::graph(actual.as_ref(), pinned.as_ref()),
        [family, command, directory] if command == "verify" => capture::verify(&root()?, family, directory.as_ref()),
        [family, command, directory] if command == "capture" && family != "elf" && family != "manifest" => capture::docker(&root()?, family, directory.as_ref()),
        [family, command, directory, cache] if family == "elf" && command == "capture" => elf::capture(&root()?, directory.as_ref(), cache.as_ref()),
        _ => Err("usage: diorama-asset-fixture {elf|decode|archive|layer|manifest} verify DIRECTORY | {decode|archive|layer} capture DIRECTORY | elf capture DIRECTORY CACHE | manifest capture DIRECTORY CACHE | archive-runtime | layer-runtime | manifest-runtime | namespace | {graph|layer-graph} ACTUAL PINNED".into()),
    }
}
