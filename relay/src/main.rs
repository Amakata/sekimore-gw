use clap::Parser;

fn main() {
    let cli = sekimore_relay::cli::Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(format!("sekimore_relay={level},russh=warn")),
    )
    .init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(sekimore_relay::cli::run(cli));
    std::process::exit(code);
}
