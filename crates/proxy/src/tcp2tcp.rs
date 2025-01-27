use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::net::TcpStream;

use crate::{ProxyResult, traffic::duplex_forward};

/// Configuration parameters for port listening and remote destination
#[derive(Clone, Debug)]
pub struct Tcp2TcpProxy {
    local_port: u16,
    remote_host: String,
    remote_port: u16,
}


impl Tcp2TcpProxy {
    pub fn new(
        local_port: u16,
        remote_host: String,
        remote_port: u16,
    ) -> ProxyResult<Self> {
        Ok(Tcp2TcpProxy {
            local_port,
            remote_host,
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
			"tcp2tcp proxy :{} -> {}:{}", self.local_port, self.remote_host, self.remote_port
		)
	}

    /// Accepts an incoming connection coming on listener and handles it on a
    /// different thread
    /// Returns the handle for the new thread or the appropriate error
    pub async fn accept(self : std::sync::Arc<Self>, listener: &TcpListener) -> ProxyResult<JoinHandle<()>> {
        let (tcp_stream, client_addr) = listener
            .accept()
			.await
            .map_err(|_| "Could not accept tcp connection")?;

        tracing::debug!("Accepted tcp connection on {:?}", client_addr);

        let remote_addr = format!("{}:{}", self.remote_host, self.remote_port);
        let h = tokio::spawn(async move {
            let server = TcpStream::connect(remote_addr.clone())
                .await
                .expect("Could not create connection");
            tracing::debug!(
                "Connected client from {:?} to {:?}",
                client_addr,
                remote_addr
            );

            let (mut client_read,  mut client_write) = tcp_stream.into_split();
            let (mut server_read, mut server_write) = server.into_split();

            duplex_forward(&mut client_read, &mut client_write, &mut server_read, &mut server_write, self.desc()).await;
            tracing::debug!("VSock Client on {:?} disconnected", client_addr);
        });
        Ok(h)
	}
}