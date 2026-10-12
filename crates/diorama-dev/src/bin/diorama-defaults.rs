fn main() {
    let raw: Vec<_> = std::env::args_os().skip(1).collect();
    if raw.first().is_some_and(|v| v == "__exec") {
        match diorama_dev::process::child_exec(&raw) {
            Ok(code) => std::process::exit(i32::from(code)),
            Err(error) => {
                eprintln!("child execution: {error}");
                std::process::exit(125);
            },
        }
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((command, rest))
            if command == "prepare-archives" && rest.len() == 2 && rest[0] == "--cache" =>
        {
            diorama_dev::defaults::archives::prepare(std::path::Path::new(&rest[1]))
        },
        Some((command, rest)) if command == "verify" => diorama_dev::defaults::verify_cli(rest),
        Some((command, rest)) if command == "capture" => diorama_dev::defaults::capture::cli(rest),
        Some((command, rest)) if command == "verify-evidence" && rest.len() <= 1 => {
            let directory = diorama_dev::defaults::directory();
            diorama_dev::defaults::capture::verify_evidence(
                &directory,
                &rest.first().map_or_else(|| directory.join("rust-evidence"), std::path::PathBuf::from),
                false,
            )
            .map(|()| 0)
        },
        _ => Err("usage: diorama-defaults <prepare-archives --cache DIR|capture|verify|verify-evidence [DIR]> ...".into()),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("defaults: {error}");
            std::process::exit(2);
        },
    }
}
