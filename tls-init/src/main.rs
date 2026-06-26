#![warn(rust_2018_idioms)]

use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use rustls::RootCertStore;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, FmtSubscriber};

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

/// TLS initiating proxy that accepts plaintext connections and forwards them over mTLS
#[derive(Parser, Debug)]
#[command(
    name = "tls-init",
    about = "A TLS initiating proxy client",
    long_about = "A TLS initiating proxy that accepts plaintext connections locally and forwards them over mTLS to a remote TLS terminator"
)]
struct Config {
    /// Address to listen on for incoming plaintext connections
    #[arg(
        short = 'l',
        long = "listen-addr",
        default_value = "127.0.0.1:50051",
        help = "Local address to listen on for incoming plaintext connections"
    )]
    listen_addr: String,

    /// Remote TLS server address (tls-term) to connect to
    #[arg(
        short = 's',
        long = "server-addr",
        help = "Remote TLS server address to connect to (host:port)"
    )]
    server_addr: String,

    /// Server name (SNI) for TLS verification
    #[arg(
        long = "server-name",
        help = "Server name for TLS certificate verification (defaults to host part of server-addr)"
    )]
    server_name: Option<String>,

    /// Path to the client certificate file for mTLS
    #[arg(
        short = 'c',
        long = "cert-path",
        help = "Path to the client certificate file (PEM format)"
    )]
    cert_path: PathBuf,

    /// Path to the client private key file
    #[arg(
        short = 'k',
        long = "key-path",
        help = "Path to the client private key file (PKCS#8 or RSA PEM format)"
    )]
    key_path: PathBuf,

    /// Path to the server CA certificate file for verifying the remote server
    #[arg(
        long = "server-ca-cert-path",
        help = "Path to the server CA certificate file (PEM format)"
    )]
    server_ca_cert_path: PathBuf,

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

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    let certs_result = certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid certificate format in {}", path.display())
        ))?;

    let certs: Vec<Certificate> = certs_result.into_iter().map(Certificate).collect();

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("No certificates found in {}", path.display())
        ));
    }

    debug!("Loaded {} certificate(s) from {}", certs.len(), path.display());
    Ok(certs)
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    let file_contents = std::fs::read(path)?;

    if let Ok(keys) = pkcs8_private_keys(&mut file_contents.as_slice()) {
        if !keys.is_empty() {
            debug!("Loaded {} PKCS#8 private key(s) from {}", keys.len(), path.display());
            return Ok(keys.into_iter().map(PrivateKey).collect());
        }
    }

    if let Ok(keys) = rsa_private_keys(&mut file_contents.as_slice()) {
        if !keys.is_empty() {
            debug!("Loaded {} RSA private key(s) from {}", keys.len(), path.display());
            return Ok(keys.into_iter().map(PrivateKey).collect());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("No valid private keys found in {}. Supported formats: PKCS#8 and RSA PEM", path.display())
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse();

    match &config.log_path {
        Some(log_dir) => {
            if let Err(e) = std::fs::create_dir_all(log_dir) {
                eprintln!("Failed to create log directory {}: {}", log_dir.display(), e);
                return Err(format!("Failed to create log directory {}: {}", log_dir.display(), e).into());
            }

            let file_appender = tracing_appender::rolling::daily(log_dir, "tls-init.log");
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
            info!("Logging to file: {}/tls-init.log.YYYY-MM-DD", log_dir.display());
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

    info!("Starting TLS initiating proxy");
    debug!("Configuration: {:?}", config);

    if !config.cert_path.exists() {
        error!("Client certificate file not found: {}", config.cert_path.display());
        return Err(format!("Client certificate file not found: {}", config.cert_path.display()).into());
    }
    if !config.key_path.exists() {
        error!("Client private key file not found: {}", config.key_path.display());
        return Err(format!("Client private key file not found: {}", config.key_path.display()).into());
    }
    if !config.server_ca_cert_path.exists() {
        error!("Server CA certificate file not found: {}", config.server_ca_cert_path.display());
        return Err(format!("Server CA certificate file not found: {}", config.server_ca_cert_path.display()).into());
    }

    let client_certs = load_certs(&config.cert_path)?;
    let mut client_keys = load_keys(&config.key_path)?;

    if client_keys.is_empty() {
        error!("No private keys were loaded from {}", config.key_path.display());
        return Err("No private keys available for TLS configuration".into());
    }
    let client_key = client_keys.remove(0);

    let server_ca_certs = load_certs(&config.server_ca_cert_path)?;
    let mut root_store = RootCertStore::empty();
    for cert in server_ca_certs {
        root_store.add(&cert).unwrap();
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)?;

    let connector = TlsConnector::from(Arc::new(tls_config));

    let server_name = config.server_name.unwrap_or_else(|| {
        config.server_addr.split(':').next().unwrap_or(&config.server_addr).to_string()
    });

    let server_name: rustls::ServerName = server_name.as_str().try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid server name for SNI"))?;

    info!("Listening on: {}", config.listen_addr);
    info!("Proxying to: {} (TLS)", config.server_addr);

    let listener = TcpListener::bind(&config.listen_addr).await?;

    let server_addr = Arc::new(config.server_addr);
    let server_name = Arc::new(server_name);

    let mut connection_id = 0u64;
    while let Ok((inbound, client_addr)) = listener.accept().await {
        connection_id += 1;
        debug!("Accepted plaintext connection {} from {}", connection_id, client_addr);

        let connector = connector.clone();
        let server_addr = server_addr.clone();
        let server_name = server_name.clone();

        tokio::spawn(async move {
            match handle_connection(inbound, connector, &server_addr, &server_name, connection_id).await {
                Ok(()) => {
                    debug!("Connection {} completed successfully", connection_id);
                }
                Err(e) => {
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
                            error!("Connection {} failed: {}", connection_id, e);
                        }
                    }
                }
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    inbound: TcpStream,
    connector: TlsConnector,
    server_addr: &str,
    server_name: &rustls::ServerName,
    connection_id: u64,
) -> Result<(), Box<dyn Error>> {
    debug!("Connecting to TLS server at {}", server_addr);

    let outbound = TcpStream::connect(server_addr).await
        .map_err(|e| {
            warn!("Failed to connect to server {}: {}", server_addr, e);
            e
        })?;

    let tls_stream = connector.connect(server_name.clone(), outbound).await
        .map_err(|e| {
            warn!("TLS handshake failed for connection {}: {}", connection_id, e);
            e
        })?;

    debug!("TLS handshake completed for connection {}", connection_id);

    let (mut ri, mut wi) = split(inbound);
    let (mut ro, mut wo) = split(tls_stream);

    let client_to_server = async {
        let result = copy(&mut ri, &mut wo).await;
        let _ = wo.shutdown().await;
        result
    };

    let server_to_client = async {
        let result = copy(&mut ro, &mut wi).await;
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
