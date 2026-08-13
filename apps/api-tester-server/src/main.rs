use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "api-tester-server",
    version,
    about = "API-AutoTester server process"
)]
struct ServerOptions {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 2712)]
    port: u16,
}

fn main() {
    let options = ServerOptions::parse();
    println!(
        "api-tester-server composition root ready at {}:{}",
        options.host, options.port
    );
}
