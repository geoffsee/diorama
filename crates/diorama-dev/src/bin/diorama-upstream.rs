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
    if let Err(error) = diorama_dev::upstream::cli(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("upstream: {error}");
        std::process::exit(1);
    }
}
