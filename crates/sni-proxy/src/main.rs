use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use hickory_sni_proxy::{Config, SniProxyServer};

#[derive(Parser, Debug)]
#[command(
    name = "hickory-sni-proxy",
    about = "TLS SNI passthrough reverse proxy"
)]
struct Args {
    /// Path to TOML configuration file.
    #[arg(short, long, default_value = "config/sni-proxy.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let config = Config::from_file(&args.config)?;
    info!(listen = %config.listen, routes = config.routes.len(), "loading SNI proxy configuration");

    let server = SniProxyServer::from_config(&config)?;
    server.run().await?;

    Ok(())
}
