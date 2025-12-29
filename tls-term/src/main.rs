//! Adapted from https://github.com/tokio-rs/tokio/blob/master/examples/proxy.rs

#![warn(rust_2018_idioms)]

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;

use futures::FutureExt;
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::RootCertStore;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

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
    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "[::1]:50052".to_string());
    let server_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "[::1]:50051".to_string());

    let cert = load_certs(Path::new("data/tls/server.pem"))?;
    let mut key = load_keys(Path::new("data/tls/server.key"))?;

    let client_ca_cert = load_certs(Path::new("data/tls/client_ca.pem"))?;
    let mut client_auth_roots = RootCertStore::empty();
    for root in client_ca_cert {
        client_auth_roots.add(&root).unwrap();
    }

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(client_auth_roots))
        .with_single_cert(cert, key.remove(0))?;
    config.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(config));

    println!("Listening on: {}", listen_addr);
    println!("Proxying to: {}", server_addr);

    let listener = TcpListener::bind(listen_addr).await?;

    while let Ok((inbound, _)) = listener.accept().await {
        let decrypted = acceptor.accept(inbound).await?;
        let transfer = transfer(decrypted, server_addr.clone()).map(|r| {
            if let Err(e) = r {
                println!("Failed to transfer; error={}", e);
            }
        });

        tokio::spawn(transfer);
    }

    Ok(())
}

async fn transfer(inbound: TlsStream<TcpStream>, proxy_addr: String) -> Result<(), Box<dyn Error>> {
    let mut outbound = TcpStream::connect(proxy_addr).await?;

    let (mut ri, mut wi) = split(inbound);
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };

    let server_to_client = async {
        copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}
