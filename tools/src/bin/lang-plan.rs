//! Which language images to build (#376): `lang-plan pr --base … --changed …` for a pull request,
//! `lang-plan publish [--lang …] [--version …]` for a publish. Prints `{"build": […], "adopt": […]}`.
//! Run from the repository root (it reads `lang/versions.yml` and `lang/Dockerfile`). The rules
//! are in `sekimore_tools::plan`.

use std::process::ExitCode;

use sekimore_tools::plan;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match plan::parse_args(&argv) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            println!("{}\n\nWhich language images to build (#376).", plan::USAGE);
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{}\nlang-plan: error: {e}", plan::USAGE);
            return ExitCode::from(2);
        }
    };
    match plan::run(&args) {
        Ok(Ok(p)) => {
            println!("{}", p.to_json());
            ExitCode::SUCCESS
        }
        Ok(Err(not_listed)) => {
            eprintln!("{not_listed}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("lang-plan: {e}");
            ExitCode::from(1)
        }
    }
}
