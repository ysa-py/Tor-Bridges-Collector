//! The `tbc` binary: parse argv, dispatch, and map errors to exit codes.
//!
//! Exit codes: `0` success, `1` runtime error, `2` usage error.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let command = match tbc_cli::parse_command(&args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(exit_code(&error));
        }
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match tbc_cli::run(&command, &mut out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(exit_code(&error))
        }
    }
}

fn exit_code(error: &tbc_cli::CliError) -> u8 {
    if error.exit_code() == 2 {
        2
    } else {
        1
    }
}
