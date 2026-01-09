//! Adapted from https://github.com/tokio-rs/tokio/blob/master/examples/proxy.rs

#![warn(rust_2018_idioms)]

use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::RootCertStore;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::{debug, error, info, instrument, warn, Level};
use tracing_subscriber::FmtSubscriber;

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

/// TLS terminating proxy that forwards connections to a backend server
#[derive(Parser, Debug)]
#[command(
    name = "tls-term",
    about = "A TLS terminating proxy server",
    long_about = "A TLS terminating proxy that accepts encrypted connections and forwards them to a backend server"
)]
struct Config {
    /// Address to listen on for incoming connections
    #[arg(
        short = 'l',
        long = "listen-addr",
        default_value = "[::1]:50052",
        help = "Address to listen on for incoming TLS connections"
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

    /// Path to the server certificate file
    #[arg(
        short = 'c',
        long = "cert-path",
        default_value = "data/tls/server.pem",
        help = "Path to the server certificate file (PEM format)"
    )]
    cert_path: PathBuf,

    /// Path to the server private key file
    #[arg(
        short = 'k',
        long = "key-path",
        default_value = "data/tls/server.key",
        help = "Path to the server private key file (PKCS#8 format)"
    )]
    key_path: PathBuf,

    /// Path to the client CA certificate file for client authentication
    #[arg(
        long = "client-ca-cert-path",
        default_value = "data/tls/client_ca.pem",
        help = "Path to the client CA certificate file for client authentication (PEM format)"
    )]
    client_ca_cert_path: PathBuf,

    /// Set the log level for output
    #[arg(
        long = "log-level",
        short = 'v',
        default_value = "info",
        help = "Set the logging level (error, warn, info, debug, trace)"
    )]
    log_level: LogLevel,
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse();

    // Initialize tracing subscriber with the specified log level
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::from(config.log_level.clone()))
        .with_target(false)
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    info!("Starting TLS terminating proxy");
    debug!("Configuration: {:?}", config);

    // Validate that certificate files exist
    if !config.cert_path.exists() {
        error!("Certificate file not found: {}", config.cert_path.display());
        return Err(format!("Certificate file not found: {}", config.cert_path.display()).into());
    }
    if !config.key_path.exists() {
        error!("Private key file not found: {}", config.key_path.display());
        return Err(format!("Private key file not found: {}", config.key_path.display()).into());
    }
    if !config.client_ca_cert_path.exists() {
        error!("Client CA certificate file not found: {}", config.client_ca_cert_path.display());
        return Err(format!("Client CA certificate file not found: {}", config.client_ca_cert_path.display()).into());
    }

    debug!("Loading certificates from {:?}", config.cert_path);

    let cert = load_certs(&config.cert_path)?;
    let mut key = load_keys(&config.key_path)?;

    let client_ca_cert = load_certs(&config.client_ca_cert_path)?;
    let mut client_auth_roots = RootCertStore::empty();
    for root in client_ca_cert {
        client_auth_roots.add(&root).unwrap();
    }

    let mut tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(client_auth_roots))
        .with_single_cert(cert, key.remove(0))?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    info!("Listening on: {}", config.listen_addr);
    info!("Proxying to: {}", config.server_addr);

    let listener = TcpListener::bind(&config.listen_addr).await?;

    let mut connection_id = 0u64;
    while let Ok((inbound, client_addr)) = listener.accept().await {
        connection_id += 1;
        debug!("Accepted connection {} from {}", connection_id, client_addr);
        
        let acceptor = acceptor.clone();
        let server_addr = config.server_addr.clone();
        
        tokio::spawn(async move {
            match acceptor.accept(inbound).await {
                Ok(decrypted) => {
                    debug!("TLS handshake completed for connection {}", connection_id);
                    if let Err(e) = handle_connection(decrypted, server_addr, connection_id).await {
                        // Only log actual errors, not normal connection closures
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
                }
                Err(e) => {
                    warn!("TLS handshake failed for connection {}: {}", connection_id, e);
                }
            }
        });
    }

    Ok(())
}

#[instrument(fields(connection_id = connection_id), skip_all)]
async fn handle_connection(inbound: TlsStream<TcpStream>, proxy_addr: String, connection_id: u64) -> Result<(), Box<dyn Error>> {
    debug!("Connecting to backend server at {}", proxy_addr);
    let mut outbound = TcpStream::connect(&proxy_addr).await
        .map_err(|e| {
            warn!("Failed to connect to backend {}: {}", proxy_addr, e);
            e
        })?;
    
    debug!("Connected to backend, starting data transfer");

    let (mut ri, mut wi) = split(inbound);
    let (mut ro, mut wo) = outbound.split();

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
