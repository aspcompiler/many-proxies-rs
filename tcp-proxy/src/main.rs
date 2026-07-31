//! Adapted from https://github.com/tokio-rs/tokio/blob/master/examples/proxy.rs

#![warn(rust_2018_idioms)]

use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use futures::FutureExt;
use std::env;
use std::error::Error;
use std::net::{Ipv6Addr, SocketAddrV6, ToSocketAddrs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "[::1]:50052".to_string());
    let server_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "[::1]:50051".to_string());

    println!("Listening on: {}", listen_addr);
    println!("Proxying to: {}", server_addr);

    let listener = TcpListener::bind(listen_addr).await?;

    while let Ok((inbound, _)) = listener.accept().await {
        let transfer = transfer(inbound, server_addr.clone()).map(|r| {
            if let Err(e) = r {
                println!("Failed to transfer; error={}", e);
            }
        });

        tokio::spawn(transfer);
    }

    Ok(())
}

fn resolve_addr(addr: &str) -> Result<std::net::SocketAddr, Box<dyn Error>> {
    // Try standard parsing first
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

async fn transfer(mut inbound: TcpStream, proxy_addr: String) -> Result<(), Box<dyn Error>> {
    let resolved = resolve_addr(&proxy_addr)?;
    let mut outbound = TcpStream::connect(resolved).await?;

    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        io::copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };

    let server_to_client = async {
        io::copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}
