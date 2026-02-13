#![cfg(feature = "early-data")]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::thread;

use rustls::pki_types::ServerName;
use rustls::{self, ClientConfig, ServerConnection, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    config: Arc<ClientConfig>,
    addr: SocketAddr,
    wrapper: impl Fn(TcpStream) -> S,
    data: &[u8],
    vectored: bool,
) -> io::Result<(TlsStream<S>, Vec<u8>)> {
    let connector = TlsConnector::from(config).early_data(true);
    let stream = TcpStream::connect(&addr).await?;
    stream.set_nodelay(true)?;
    let stream = wrapper(stream);

    let domain = ServerName::try_from("foobar.com").unwrap();

    let mut stream = connector.connect(domain, stream).await?;
    utils::write(&mut stream, data, vectored).await?;
    stream.flush().await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    Ok((stream, buf))
}

#[tokio::test]
async fn test_0rtt_impl() {
    tracing_subscriber::fmt::init();
    let (mut server, mut client) = utils::make_configs();
    server.max_early_data_size = 8192;
    let server = Arc::new(server);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _addr) = listener.accept().await.unwrap();

            sock.set_nodelay(true).unwrap();
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), sock);

                let start = acceptor.await.unwrap();
                let ch = start.client_hello();
                tracing::info!("receive a new conn:{:?}", ch);
                //let mut buf = Vec::new();
                let mut stream = start
                    .into_stream_with(server, |x| {
                        // if let Some(mut earyly_data) = x.early_data() {
                        //     let n = earyly_data.read_to_end(&mut buf).unwrap();
                        //     tracing::info!("early data reveived {n} bytes:{:?}", buf);
                        // }
                    })
                    .await
                    .unwrap();
                // if let Some(mut earyly_data) = stream.get_mut().1.early_data() {
                //     let n = earyly_data.read_to_end(&mut buf).unwrap();
                //     tracing::info!("early data reveived {n} bytes:{:?}", buf);
                // }
                let mut buf = Vec::new();
                let _ = stream
                    .read_to_end(&mut buf)
                    .await
                    .map_err(|x| tracing::error!("server read error:{}", x));
                tracing::info!("server received: {}", String::from_utf8_lossy(&buf));

                stream.write_all(b"bye").await.unwrap();
                // if let Some(mut early_data) = conn.early_data() {
                //     let mut buf = Vec::new();
                //     early_data.read_to_end(&mut buf).unwrap();
                //     let mut stream = Stream::new(&mut conn, &mut sock);
                //     stream.write_all(b"EARLY:").unwrap();
                //     stream.write_all(&buf).unwrap();
                // }

                // let mut stream = Stream::new(&mut conn, &mut sock);
                // stream.write_all(b"LATE:").unwrap();
                loop {
                    let mut buf = [0; 1024];
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        // conn.send_close_notify();
                        // conn.complete_io(&mut sock).unwrap();
                        stream.flush().await.unwrap();
                        stream.shutdown().await.unwrap();
                        break;
                    }
                    stream.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
    });

    client.enable_early_data = true;
    let client = Arc::new(client);
    let addr = SocketAddr::from(([127, 0, 0, 1], server_port));

    let wrapper = |s| s;
    tracing::warn!("client sending");
    let (mut io, buf) = send(client.clone(), addr, &wrapper, b"hello", false)
        .await
        .map_err(|x| tracing::error!("client send error:{}", x))
        .unwrap();
    assert!(!io.get_ref().1.is_early_data_accepted());

    tracing::info!("client received: {}", String::from_utf8_lossy(&buf));

    tracing::warn!("client sending");
    let (mut io, buf) = send(client, addr, wrapper, b"world!", false).await.unwrap();

    assert!(io.get_ref().1.is_early_data_accepted());
    tracing::info!("client received: {}", String::from_utf8_lossy(&buf));
}

// Include `utils` module
include!("utils.rs");
