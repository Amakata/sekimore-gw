//! `sgw-agent`: the AI's command in the dev container (#257). Everything is in
//! `sekimore_relay::cli::agent::standalone`.
fn main() {
    std::process::exit(sekimore_relay::cli::agent::standalone::main());
}
