use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use threadpool::ThreadPool;
use vsock::{VsockAddr, VsockStream};

use crate::{ProxyResult, traffic::duplex_forward};

/// Configuration parameters for port listening and remote destination
pub struct TcpProxy {
    local_port: u16,
    remote_cid: u32,
    remote_port: u32,
    pool: ThreadPool,
}

impl TcpProxy {
    pub fn new(
        local_port: u16,
        remote_cid: u32,
        remote_port: u32,
        num_workers: usize,
    ) -> ProxyResult<Self> {
        let pool = ThreadPool::new(num_workers);

        Ok(TcpProxy {
            local_port,
            remote_cid,
            remote_port,
            pool,
        })
    }

    /// Creates a listening socket
    /// Returns the file descriptor for it or the appropriate error
    pub fn listen(&self) -> ProxyResult<TcpListener> {
		let addr =  format!("0.0.0.0:{}", self.local_port);
        let listener = TcpListener::bind(addr.clone()).map_err(|_| format!("Could not bind to tcp port {}", self.local_port))?;

        tracing::info!("Bound to host tcp port {:?}", addr);

        Ok(listener)
    }

    /// Accepts an incoming connection coming on listener and handles it on a
    /// different thread
    /// Returns the handle for the new thread or the appropriate error
    pub fn accept(&mut self, listener: &TcpListener) -> ProxyResult<()> {
        let (mut client, client_addr) = listener
            .accept()
            .map_err(|_| "Could not accept tcp connection")?;

        tracing::debug!("Accepted tcp connection on {:?}", client_addr);
		let remote_cid = self.remote_cid;
		let remote_port = self.remote_port;
        self.pool.execute(move || {

			let sockaddr = VsockAddr::new(remote_cid, remote_port);
			let mut server = VsockStream::connect(&sockaddr).expect("Could not connect");

            tracing::debug!("Connected client from {:?} to {:?}", client_addr, sockaddr);

            let client_socket = client.as_raw_fd();
            let server_socket = server.as_raw_fd();

            duplex_forward(client_socket, server_socket, &mut client, &mut server);
            tracing::debug!("TCP Client on {:?} disconnected", client_addr);
        });

        Ok(())
	}
}