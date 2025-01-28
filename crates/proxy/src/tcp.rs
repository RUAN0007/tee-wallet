use tokio::net::TcpListener;
use tokio_vsock::{VsockStream, VsockAddr};
use tokio::task::JoinHandle;
use std::sync::Arc;

use crate::{ProxyResult, traffic::duplex_forward};

/// Configuration parameters for port listening and remote destination
#[derive(Clone, Debug)]
pub struct TcpProxy {
    local_port: u16,
    remote_cid: u32,
    remote_port: u32,
}

impl TcpProxy {
    pub fn new(
        local_port: u16,
        remote_cid: u32,
        remote_port: u32,
    ) -> ProxyResult<Self> {
        Ok(TcpProxy {
            local_port,
            remote_cid,
            remote_port,
        })
    }

    /// Creates a listening socket
    /// Returns the file descriptor for it or the appropriate error
    pub async fn listen(&self) -> ProxyResult<TcpListener> {
		let addr =  format!("0.0.0.0:{}", self.local_port);
        let listener = TcpListener::bind(addr.clone()).await.map_err(|_| format!("Could not bind to tcp port {}", self.local_port))?;

        tracing::info!("Bound to host tcp port {:?}", addr);

        Ok(listener)
    }

	pub fn desc(&self) -> String {
		format!(
			"tcp proxy :{} -> {}:{}", self.local_port, self.remote_cid, self.remote_port
		)
	}

    /// Accepts an incoming connection coming on listener and handles it on a
    /// different thread
    /// Returns the handle for the new thread or the appropriate error
    pub async fn accept(self : Arc<Self>, listener: &TcpListener) -> ProxyResult<JoinHandle<()>> {
        let (tcp_stream, client_addr) = listener
            .accept()
			.await
            .map_err(|_| "Could not accept tcp connection")?;

        tracing::debug!("Accepted tcp connection on {:?}", client_addr);
		let remote_cid = self.remote_cid;
		let remote_port = self.remote_port;

		let h = tokio::spawn(async move {
			let vsock_addr = VsockAddr::new(remote_cid, remote_port);
			let vsock_stream = VsockStream::connect(vsock_addr).await.expect("Could not connect");

			let (mut client_read,  mut client_write) = tcp_stream.into_split();
            let (mut server_read, mut server_write) = vsock_stream.into_split();

            duplex_forward(&mut client_read, &mut client_write, &mut server_read, &mut server_write, self.desc()).await;
            tracing::debug!("TCP Client on {:?} disconnected", client_addr);
		});

        Ok(h)
	}
}

