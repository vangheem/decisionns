use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use clap::Parser;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use decisionns::admin;
use decisionns::app::App;
use decisionns::config::Config;
use decisionns::dns;

#[derive(Parser, Debug)]
#[command(name = "decisionns", about = "Home DNS resolver gated by lists and decision models")]
struct Cli {
    /// Config file. If omitted, ./config.toml is used when present, otherwise dev defaults (DNS on 5353).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Replace the admin password from the config or environment, or generate a new one.
    #[arg(long)]
    reset_admin_password: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("decisionns=info")))
        .init();

    let cli = Cli::parse();
    let mut config = load_config(cli.config.as_deref())?;
    config.apply_env();

    let (app, generated) = App::open(&config, cli.reset_admin_password)?;
    if let Some(password) = generated {
        let path = config.data_dir.join("initial-admin-password.txt");
        std::fs::write(&path, &password).context("write initial password file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        eprintln!();
        eprintln!("  Initial admin password: {password}");
        eprintln!("  Also written to {}", path.display());
        eprintln!("  Change it in the admin UI. This file is removed when you do.");
        eprintln!();
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dns_bound = 0usize;
    for addr in &config.dns_listen {
        match UdpSocket::bind(addr).await {
            Ok(sock) => {
                tracing::info!(%addr, "dns udp listening");
                let app = app.clone();
                let rx = shutdown_rx.clone();
                tokio::spawn(dns::serve_udp(sock, app, rx));
                dns_bound += 1;
            }
            Err(e) => tracing::error!(%addr, error = %e, "dns udp bind failed"),
        }
        if config.dns_tcp {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!(%addr, "dns tcp listening");
                    let app = app.clone();
                    let rx = shutdown_rx.clone();
                    tokio::spawn(dns::serve_tcp(listener, app, rx));
                }
                Err(e) => tracing::error!(%addr, error = %e, "dns tcp bind failed"),
            }
        }
    }
    if dns_bound == 0 {
        anyhow::bail!(
            "no DNS sockets bound. Port 53 needs root or cap_net_bind_service. For a laptop trial, omit the config file to listen on 5353."
        );
    }

    let admin = admin::router(app.clone()).layer(DefaultBodyLimit::max(2 * 1024 * 1024));
    let listener = TcpListener::bind(config.admin_listen)
        .await
        .with_context(|| format!("admin bind {}", config.admin_listen))?;
    tracing::info!(addr = %config.admin_listen, "admin listening");
    eprintln!("DecisionNS {}", decisionns::VERSION);
    eprintln!("  DNS   {}", config.dns_listen.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "));
    eprintln!("  Admin http://{}", display_admin(&config.admin_listen));
    eprintln!("  Data  {}", config.data_dir.display());
    eprintln!();
    eprintln!("Point the router's DHCP DNS server at this machine's LAN address.");
    eprintln!("Per-device profiles only work when clients query DecisionNS directly.");

    let app_for_shutdown = app.clone();
    let shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        axum::serve(listener, admin.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move {
                let mut shutdown = shutdown;
                let _ = shutdown.changed().await;
            })
            .await
            .ok();
        let _ = app_for_shutdown;
    });

    tokio::signal::ctrl_c().await.ok();
    eprintln!("shutting down");
    let _ = shutdown_tx.send(true);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Ok(())
}

fn load_config(explicit: Option<&std::path::Path>) -> anyhow::Result<Config> {
    if let Some(path) = explicit {
        return Config::load(path);
    }
    let default = PathBuf::from("config.toml");
    if default.exists() {
        return Config::load(&default);
    }
    eprintln!("No config.toml found. Using dev defaults: DNS on port 5353, admin on 8080.");
    eprintln!("Copy config.example.toml to config.toml and set port 53 before pointing a router here.");
    Ok(Config::dev_default())
}

fn display_admin(addr: &SocketAddr) -> String {
    if addr.ip().is_unspecified() {
        format!("127.0.0.1:{}", addr.port())
    } else {
        addr.to_string()
    }
}
