// Copyright 2019-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Contains code for Proxy, a library used for translating vsock traffic to
/// TCP traffic
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use threadpool::ThreadPool;
use vsock::{VsockAddr, VsockListener};

use crate::dns::DnsResolutionInfo;
use crate::{dns, IpAddrType, ProxyResult, traffic::duplex_forward};

pub const VSOCK_HOST_CID: u32 = 3; // according to https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
pub const VSOCK_PROXY_PORT: u32 = 8000;

/// Configuration parameters for port listening and remote destination
#[derive(Clone, Debug)]
pub struct VsockProxy {
    local_port: u32,
    remote_host: String,
    remote_port: u16,
    dns_resolution_info: Option<DnsResolutionInfo>,
    pool: ThreadPool, // TODO: Use tokio instead of threadpool
    ip_addr_type: IpAddrType,
}

impl VsockProxy {
    pub fn new(
        local_port: u32,
        remote_host: String,
        remote_port: u16,
        num_workers: usize,
        ip_addr_type: IpAddrType,
    ) -> ProxyResult<Self> {
        let pool = ThreadPool::new(num_workers);
        let dns_resolution_info: Option<DnsResolutionInfo> = None;

        Ok(VsockProxy {
            local_port,
            remote_host,
            remote_port,
            dns_resolution_info,
            pool,
            ip_addr_type,
        })
    }

    /// Creates a listening socket
    /// Returns the file descriptor for it or the appropriate error
    pub fn listen(&self) -> ProxyResult<VsockListener> {
        let sockaddr = VsockAddr::new(VSOCK_HOST_CID, self.local_port);
        let listener = VsockListener::bind(&sockaddr)
            .map_err(|_| format!("Could not bind to {:?}", sockaddr))?;
        tracing::info!("Bound to host sock {:?}", sockaddr);

        Ok(listener)
    }

    /// Accepts an incoming connection coming on listener and handles it on a
    /// different thread
    /// Returns the handle for the new thread or the appropriate error
    pub fn accept(&mut self, listener: &VsockListener) -> ProxyResult<()> {
        let (mut client, client_addr) = listener
            .accept()
            .map_err(|_| "Could not accept vsock connection")?;

        tracing::debug!("Accepted vsock connection on {:?}", client_addr);

        let dns_needs_resolution = self
            .dns_resolution_info
            .map_or(true, |info| info.is_expired());

        let remote_addr = if dns_needs_resolution {
            tracing::debug!("Resolving hostname: {}.", self.remote_host);

            let dns_resolution = dns::resolve_single(&self.remote_host, self.ip_addr_type)?;

            tracing::debug!(
                "Using IP \"{:?}\" for the given server \"{}\". (TTL: {} secs)",
                dns_resolution.ip_addr(),
                self.remote_host,
                dns_resolution.ttl().num_seconds()
            );

            self.dns_resolution_info = Some(dns_resolution);
            dns_resolution.ip_addr()
        } else {
            self.dns_resolution_info
                .ok_or("DNS resolution failed!")?
                .ip_addr()
        };

        let sockaddr = SocketAddr::new(remote_addr, self.remote_port);
        self.pool.execute(move || {
            let mut server = TcpStream::connect(sockaddr).expect("Could not create connection");
            tracing::debug!("Connected client from {:?} to {:?}", client_addr, sockaddr);

            let client_socket = client.as_raw_fd();
            let server_socket = server.as_raw_fd();

            duplex_forward(client_socket, server_socket, &mut client, &mut server);
            tracing::debug!("VSock Client on {:?} disconnected", client_addr);
        });

        Ok(())
    }
}
