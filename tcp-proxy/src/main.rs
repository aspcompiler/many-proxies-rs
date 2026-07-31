//! Adapted from https://github.com/tokio-rs/tokio/blob/master/examples/proxy.rs

#![warn(rust_2018_idioms)]

use std::error::Error;
use std::io::ErrorKind;
use std::net::{Ipv6Addr, SocketAddrV6, ToSocketAddrs};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, instrument, warn, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, FmtSubscriber};

/// Log level for tracing output
#[derive(ValueEnum, Clone, Debug)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => Level::ERROR,
            LogLevel::Warn => Level::WARN,
            LogLevel::Info => Level::INFO,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Trace => Level::TRACE,
        }
    }
}

/// TCP proxy that forwards connections to a backend server
#[derive(Parser, Debug)]
#[command(
    name = "tcp-proxy",
    about = "A TCP proxy server",
    long_about = "A TCP proxy that accepts connections and forwards them to a backend server"
)]
struct Config {
    /// Address to listen on for incoming connections
    #[arg(
        short = 'l',
        long = "listen-addr",
        default_value = "[::1]:50052",
        help = "Address to listen on for incoming connections"
    )]
    listen_addr: String,

    /// Backend server address to proxy connections to
    #[arg(
        short = 's',
        long = "server-addr",
        default_value = "[::1]:50051",
        help = "Backend server address to forward connections to"
    )]
    server_addr: String,

    /// Set the log level for output
    #[arg(
        long = "log-level",
        short = 'v',
        default_value = "info",
        help = "Set the logging level (error, warn, info, debug, trace)"
    )]
    log_level: LogLevel,

    /// Optional directory path for file logging with daily rotation
    #[arg(
        long = "log-path",
        help = "Directory path for log files with daily rotation (logs to console if not specified)"
    )]
    log_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse();

    // Initialize tracing subscriber based on log configuration
    match &config.log_path {
        Some(log_dir) => {
            if let Err(e) = std::fs::create_dir_all(log_dir) {
                eprintln!("Failed to create log directory {}: {}", log_dir.display(), e);
                return Err(format!("Failed to create log directory {}: {}", log_dir.display(), e).into());
            }

            let file_appender = tracing_appender::rolling::daily(log_dir, "tcp-proxy.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

            let subscriber = tracing_subscriber::registry()
                .with(
                    fmt::layer()
                        .with_writer(non_blocking)
                        .with_target(false)
                        .with_ansi(false)
                )
                .with(EnvFilter::from_default_env().add_directive(Level::from(config.log_level.clone()).into()));

            tracing::subscriber::set_global_default(subscriber)
                .expect("Failed to set tracing subscriber");

            std::mem::forget(_guard);

            info!("Logging to file: {}/tcp-proxy.log.YYYY-MM-DD", log_dir.display());
        }
        None => {
            let subscriber = FmtSubscriber::builder()
                .with_max_level(Level::from(config.log_level.clone()))
                .with_target(false)
                .finish();

            tracing::subscriber::set_global_default(subscriber)
                .expect("Failed to set tracing subscriber");

            info!("Logging to console");
        }
    }

    info!("Starting TCP proxy");
    debug!("Configuration: {:?}", config);

    info!("Listening on: {}", config.listen_addr);
    info!("Proxying to: {}", config.server_addr);

    let listener = TcpListener::bind(&config.listen_addr).await?;

    let mut connection_id = 0u64;
    while let Ok((inbound, client_addr)) = listener.accept().await {
        connection_id += 1;
        debug!("Accepted connection {} from {}", connection_id, client_addr);

        let server_addr = config.server_addr.clone();

        tokio::spawn(async move {
            if let Err(e) = transfer(inbound, server_addr, connection_id).await {
                match e.downcast_ref::<io::Error>() {
                    Some(io_error) => match io_error.kind() {
                        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => {
                            debug!("Connection {} closed normally: {}", connection_id, e);
                        }
                        ErrorKind::ConnectionAborted => {
                            info!("Connection {} aborted: {}", connection_id, e);
                        }
                        _ => {
                            warn!("Connection {} error: {}", connection_id, e);
                        }
                    }
                    None => {
                        error!("Connection {} failed with non-IO error: {}", connection_id, e);
                    }
                }
            } else {
                debug!("Connection {} completed successfully", connection_id);
            }
        });
    }

    Ok(())
}

fn resolve_addr(addr: &str) -> Result<std::net::SocketAddr, Box<dyn Error>> {
    if let Ok(sock) = addr.parse::<std::net::SocketAddr>() {
        return Ok(sock);
    }

    // Handle [ipv6%zone]:port format
    if let Some(s) = addr.strip_prefix('[') {
        if let Some((host_zone, port_str)) = s.rsplit_once("]:") {
            let port: u16 = port_str.parse()?;
            if let Some((ip_str, zone)) = host_zone.rsplit_once('%') {
                let ip: Ipv6Addr = ip_str.parse()?;
                let scope_id = zone.parse::<u32>().unwrap_or_else(|_| {
                    unsafe { libc::if_nametoindex(std::ffi::CString::new(zone).unwrap().as_ptr()) }
                });
                return Ok(std::net::SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)));
            }
        }
    }

    // Fall back to DNS resolution
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| "could not resolve address".into())
}

#[instrument(fields(connection_id = connection_id), skip_all)]
async fn transfer(mut inbound: TcpStream, proxy_addr: String, connection_id: u64) -> Result<(), Box<dyn Error>> {
    let resolved = resolve_addr(&proxy_addr)?;
    debug!("Connecting to backend server at {}", resolved);

    let mut outbound = TcpStream::connect(resolved).await
        .map_err(|e| {
            warn!("Failed to connect to backend {}: {}", resolved, e);
            e
        })?;

    debug!("Connected to backend, starting data transfer");

    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        let result = io::copy(&mut ri, &mut wo).await;
        let _ = wo.shutdown().await;
        result
    };

    let server_to_client = async {
        let result = io::copy(&mut ro, &mut wi).await;
        let _ = wi.shutdown().await;
        result
    };

    match tokio::try_join!(client_to_server, server_to_client) {
        Ok((bytes_to_server, bytes_to_client)) => {
            debug!("Transfer completed: {} bytes to server, {} bytes to client", bytes_to_server, bytes_to_client);
            Ok(())
        }
        Err(e) => Err(e.into())
    }
}
