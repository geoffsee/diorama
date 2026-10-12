use std::{path::Path, process::ExitCode};
fn main() -> ExitCode {
    let result = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))
        .and_then(|root| diorama_dev::language_policy::check(&root));
    match result {
        Ok(issues) if issues.is_empty() => {
            println!("repository language policy passed");
            ExitCode::SUCCESS
        },
        Ok(issues) => {
            for issue in issues {
                eprintln!("{issue}");
            }
            ExitCode::FAILURE
        },
        Err(error) => {
            eprintln!("language policy failed: {error}");
            ExitCode::from(2)
        },
    }
}
