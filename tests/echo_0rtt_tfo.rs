#![cfg(feature = "early-data")]

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use rustls::pki_types::ServerName;
use rustls::{self, ClientConfig, ServerConnection, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};
use tokio_tfo::TfoStream;

#[tokio::test]
async fn test_0rtt_echo() -> io::Result<()> {
    tracing_subscriber::fmt::init();

    // 1. Setup configurations
    let (mut server_config, mut client_config) = utils::make_configs();
    server_config.max_early_data_size = 8192;
    server_config.send_half_rtt_data = true;
    client_config.enable_early_data = true;

    let server_config = Arc::new(server_config);
    let client_config = Arc::new(client_config);

    // 2. Start Server
    let listener = tokio_tfo::TfoListener::bind("127.0.0.1:0".parse().unwrap()).await?;
    let addr = listener.local_addr()?;
    tracing::info!("Server listening on {}", addr);

    tokio::spawn(async move {
        let server_config_clone = server_config.clone();
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Listener accept error: {}", e);
                    break;
                }
            };
            let acceptor = LazyConfigAcceptor::new(Default::default(), stream);
            tracing::info!("Accepted connection from {}", peer_addr);
            let server_config_clone = server_config_clone.clone();
            tokio::spawn(async move {
                tracing::info!("Starting TLS handshake for {}", peer_addr);
                let mut stream = match acceptor.await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("TLS Accept error for {}: {}", peer_addr, e);
                        return;
                    }
                };
                let mut stream = stream
                    .into_stream(server_config_clone.clone())
                    .await
                    .unwrap();
                tracing::info!("TLS handshake complete for {}", peer_addr);

                let mut buf = [0u8; 1024];
                loop {
                    tracing::info!("Server waiting for data from {}", peer_addr);
                    let n = match stream.read(&mut buf).await {
                        Ok(n) if n == 0 => {
                            tracing::info!("Server received EOF from {}", peer_addr);
                            break;
                        }
                        Ok(n) => {
                            tracing::info!(
                                "Server received {} bytes from {}: {:?}",
                                n,
                                peer_addr,
                                &buf[..n]
                            );
                            n
                        }
                        Err(e) => {
                            tracing::error!("Server read error from {}: {}", peer_addr, e);
                            break;
                        }
                    };

                    tracing::info!("Server writing {} bytes back to {}", n, peer_addr);
                    if let Err(e) = stream.write_all(&buf[..n]).await {
                        tracing::error!("Server write error to {}: {}", peer_addr, e);
                        break;
                    }
                    tracing::info!("Server write complete to {}", peer_addr);
                }
                tracing::info!("Server shutting down stream for {}", peer_addr);
                let _ = stream.shutdown().await;
                tracing::info!("Server stream shutdown complete for {}", peer_addr);
            });
        }
    });

    // 3. Client - First Connection (to get ticket)
    let connector = TlsConnector::from(client_config.clone()).early_data(true);
    let domain = ServerName::try_from("foobar.com").unwrap();

    {
        tracing::info!("Client 1 connecting to {}", addr);
        let stream = TfoStream::connect(addr).await?;
        let mut stream = connector.connect(domain.clone(), stream).await?;
        tracing::info!("Client 1 connected");

        stream.write_all(b"Hello").await?;
        stream.flush().await?;
        tracing::info!("Client 1 sent Hello");

        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await?;
        tracing::info!("Client 1 received response");
        assert_eq!(&buf, b"Hello");

        tracing::info!("Client 1 shutting down");
        stream.shutdown().await?;
        tracing::info!("Client 1 shutdown complete, reading to end");

        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await?;
        tracing::info!("Client 1 read_to_end complete ({} bytes)", rest.len());
    }
    tracing::info!("First connection done");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 4. Client - Second Connection (0-RTT)
    {
        tracing::info!("Client 2 connecting to {}", addr);
        let stream = TfoStream::connect(addr).await?;
        // Re-use connector to utilize the session store in client_config
        let mut stream = connector.connect(domain, stream).await?;
        tracing::info!("Client 2 connect/handshake initiated");

        // Write 0-RTT data
        let msg = b"0-RTT Echo";

        tracing::info!("Client 2 writing 0-RTT data");
        stream.write_all(msg).await?;
        stream.flush().await?;
        tracing::info!("Client 2 write/flush complete");

        let is_early_data = stream.get_ref().1.is_early_data_accepted();
        tracing::info!("Client 2 early data accepted: {}", is_early_data);
        assert!(is_early_data, "Early data should be accepted");

        let mut buf = vec![0u8; msg.len()];
        stream.read_exact(&mut buf).await?;
        tracing::info!("Client 2 read response");
        assert_eq!(&buf, msg);
    }

    Ok(())
}

include!("utils.rs");
