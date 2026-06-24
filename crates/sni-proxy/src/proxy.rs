//! TCP accept loop: peek ClientHello, route by SNI, forward without TLS termination.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};
use tracing::{debug, info, warn};

use crate::client_hello::{MAX_CLIENT_HELLO_BYTES, extract_sni_from_buffer};
use crate::config::Config;
use crate::error::{Result, SniProxyError};
use crate::router::RouteTable;

/// Running SNI passthrough proxy server.
pub struct SniProxyServer {
    listen: SocketAddr,
    routes: Arc<RouteTable>,
    peek_timeout: Duration,
}

impl SniProxyServer {
    pub fn from_config(config: &Config) -> Result<Self> {
        let listen: SocketAddr = config.listen.parse().map_err(|e| {
            SniProxyError::Config(format!("invalid listen {:?}: {e}", config.listen))
        })?;

        Ok(Self {
            listen,
            routes: Arc::new(config.route_table()?),
            peek_timeout: Duration::from_millis(config.peek_timeout_ms),
        })
    }

    /// Accept connections until the listener is closed.
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.listen).await?;
        info!(%self.listen, "SNI passthrough proxy listening");

        loop {
            let (stream, peer) = listener.accept().await?;
            let routes = Arc::clone(&self.routes);
            let peek_timeout = self.peek_timeout;
            tokio::spawn(async move {
                if let Err(err) = handle_connection(stream, peer, routes, peek_timeout).await {
                    debug!(%peer, %err, "connection closed");
                }
            });
        }
    }
}

async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    routes: Arc<RouteTable>,
    peek_timeout: Duration,
) -> Result<()> {
    let (sni, peeked) = peek_client_hello(&mut client, peek_timeout).await?;
    let backend_addr = routes.resolve(&sni)?;

    debug!(%peer, %sni, %backend_addr, "routing connection");

    let mut upstream = TcpStream::connect(&backend_addr).await.map_err(|e| {
        SniProxyError::Io(std::io::Error::new(
            e.kind(),
            format!("connect to backend {backend_addr}: {e}"),
        ))
    })?;

    upstream.write_all(&peeked).await?;

    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

    tokio::select! {
        res = client_to_upstream => {
            if let Err(e) = res {
                warn!(%peer, %sni, %e, "client → upstream copy failed");
            }
        }
        res = upstream_to_client => {
            if let Err(e) = res {
                warn!(%peer, %sni, %e, "upstream → client copy failed");
            }
        }
    }

    Ok(())
}

async fn peek_client_hello(
    stream: &mut TcpStream,
    peek_timeout: Duration,
) -> Result<(String, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(512);
    let deadline = peek_timeout;

    loop {
        if buffer.len() >= MAX_CLIENT_HELLO_BYTES {
            return Err(SniProxyError::ClientHello(format!(
                "ClientHello exceeded {MAX_CLIENT_HELLO_BYTES} bytes"
            )));
        }

        let mut chunk = [0u8; 1024];
        let read = timeout(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| SniProxyError::ClientHello("timeout waiting for ClientHello".into()))??;

        if read == 0 {
            return Err(SniProxyError::ClientHello(
                "connection closed before ClientHello".into(),
            ));
        }

        buffer.extend_from_slice(&chunk[..read]);

        match extract_sni_from_buffer(&buffer)? {
            Some(sni) => return Ok((sni, buffer)),
            None => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::client_hello::build_test_client_hello;

    #[tokio::test]
    async fn forwards_client_hello_to_backend_by_sni() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();

        let backend_task = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });

        let mut routes_map = HashMap::new();
        routes_map.insert("api.example.com".into(), "test".into());
        let mut backends = HashMap::new();
        backends.insert("test".into(), backend_addr.to_string());
        let routes = Arc::new(RouteTable::from_config(&routes_map, &backends, None).unwrap());

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        let proxy_task = tokio::spawn(async move {
            let (stream, peer) = proxy.accept().await.unwrap();
            handle_connection(stream, peer, routes, Duration::from_secs(2))
                .await
                .unwrap();
        });

        let hello = build_test_client_hello("api.example.com");
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&hello).await.unwrap();
        let mut response_buf = [0u8; 16];
        let _ = client.read(&mut response_buf).await;

        proxy_task.await.unwrap();
        let received = backend_task.await.unwrap();
        assert_eq!(received, hello);
    }
}
