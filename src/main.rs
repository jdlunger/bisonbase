use anyhow::Context;
use tracing_subscriber::EnvFilter;
use bisonbase::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bisonbase=info,tower_http=info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mut recover = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "recovery-link" => {
                recover = Some(
                    args.next()
                        .context("usage: bisonbase recovery-link <username>")?,
                )
            }
            "-h" | "--help" => {
                println!(
                    "usage: bisonbase\n       \
                     bisonbase recovery-link <username>\n\n\
                     Serves http://localhost:8080 with data in ./data.\n\n\
                     recovery-link prints a one-time link (valid 24 hours) that lets the user add\n\
                     a new passkey, for when nobody who can log in is an admin."
                );
                return Ok(());
            }
            "-V" | "--version" => {
                println!("bisonbase {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }
    let cfg = Config::default();
    if let Some(username) = recover {
        println!("{}", bisonbase::recovery_link(cfg, &username).await?);
        return Ok(());
    }
    bisonbase::start(cfg)
        .await?
        .run_until(shutdown_signal())
        .await
}

/// Ctrl-C, or SIGTERM (what Docker and systemd send to stop a service).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
