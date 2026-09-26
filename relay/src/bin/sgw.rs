//! `sgw`: the operator's tool on the host (#234). Everything is in `sekimore_relay::host`.
fn main() {
    std::process::exit(sekimore_relay::host::cli::main());
}
