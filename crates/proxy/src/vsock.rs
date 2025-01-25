// Copyright 2019-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Contains code for Proxy, a library used for translating vsock traffic to
/// TCP traffic

use tokio_vsock::VsockAddr;
use tokio_vsock::VsockListener;

use tokio::task::JoinHandle;
use tokio::net::TcpStream;
use std::net::SocketAddr;
use crate::{dns, IpAddrType, ProxyResult, traffic::duplex_forward};

pub const VSOCK_HOST_CID: u32 = 3; // according to https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html

/// Configuration parameters for port listening and remote destination
#[derive(Clone, Debug)]
pub struct VsockProxy {
    local_port: u32,
    remote_host: String,
    remote_port: u16,
    ip_addr_type: IpAddrType,
}

impl VsockProxy {
    pub fn new(
        local_port: u32,
        remote_host: String,
        remote_port: u16,
        ip_addr_type: IpAddrType,
    ) -> ProxyResult<Self> {
        Ok(VsockProxy {
            local_port,
            remote_host,
            remote_port,
            ip_addr_type,
        })
    }

    pub fn desc(&self) -> String {
        format!(
            "vsock proxy {}:{} -> {}:{}",
            VSOCK_HOST_CID, self.local_port, self.remote_host, self.remote_port
        )
    }

    /// Creates a listening socket
    /// Returns the file descriptor for it or the appropriate error
    pub async fn listen(&self) -> ProxyResult<VsockListener> {

        let sockaddr = VsockAddr::new(VSOCK_HOST_CID, self.local_port);
        let listener = VsockListener::bind(sockaddr)
            .map_err(|_| format!("Could not bind to {:?}", sockaddr))?;
        tracing::info!("Bound to host sock {:?}", sockaddr);

        Ok(listener)
    }

    /// Accepts an incoming connection coming on listener and handles it on a
    /// different thread
    /// Returns the handle for the new thread or the appropriate error
    pub async fn accept(self: std::sync::Arc<Self>, listener: &VsockListener) -> ProxyResult<JoinHandle<()>>  {
    // pub async fn accept(self: &mut Self, listener: &VsockListener) -> ProxyResult<JoinHandle<()>>  {
        let (vsock_stream, client_addr) = listener
            .accept()
            .await
            .map_err(|_| "Could not accept vsock connection")?;

        tracing::debug!("Accepted vsock connection on {:?}", client_addr);
        let dns_resolution = dns::resolve_single(&self.remote_host, self.ip_addr_type)?;

        // let dns_needs_resolution = self
        //     .dns_resolution_info
        //     .map_or(true, |info| info.is_expired());

        // let remote_addr = if dns_needs_resolution {
        //     tracing::debug!("Resolving hostname: {}.", self.remote_host);

        //     let dns_resolution = dns::resolve_single(&self.remote_host, self.ip_addr_type)?;

        //     tracing::debug!(
        //         "Using IP \"{:?}\" for the given server \"{}\". (TTL: {} secs)",
        //         dns_resolution.ip_addr(),
        //         self.remote_host,
        //         dns_resolution.ttl().num_seconds()
        //     );

        //     self.getdns_resolution_info = Some(dns_resolution);
        //     dns_resolution.ip_addr()
        // } else {
        //     self.dns_resolution_info
        //         .ok_or("DNS resolution failed!")?
        //         .ip_addr()
        // };

        let remote_addr = SocketAddr::new(dns_resolution.ip_addr(), self.remote_port);
        let h = tokio::spawn(async move {
            let server = TcpStream::connect(remote_addr)
                .await
                .expect("Could not create connection");
            tracing::debug!(
                "Connected client from {:?} to {:?}",
                client_addr,
                remote_addr
            );

            let (mut client_read,  mut client_write) = vsock_stream.into_split();
            let (mut server_read, mut server_write) = server.into_split();

            duplex_forward(&mut client_read, &mut client_write, &mut server_read, &mut server_write, self.desc()).await;
            tracing::debug!("VSock Client on {:?} disconnected", client_addr);
        });
        Ok(h)
    }
    

    // pub async fn accept2(self : &mut Self, listener: &VsockListener) -> ProxyResult<()>  {
    //     let (vsock_stream, client_addr) = listener
    //         .accept()
    //         .await
    //         .map_err(|_| "Could not accept vsock connection")?;

    //     tracing::debug!("Accepted vsock connection on {:?}", client_addr);
    //     let dns_needs_resolution = self
    //         .dns_resolution_info
    //         .map_or(true, |info| info.is_expired());

    //     let remote_addr = if dns_needs_resolution {
    //         tracing::debug!("Resolving hostname: {}.", self.remote_host);

    //         let dns_resolution = dns::resolve_single(&self.remote_host, self.ip_addr_type)?;

    //         tracing::debug!(
    //             "Using IP \"{:?}\" for the given server \"{}\". (TTL: {} secs)",
    //             dns_resolution.ip_addr(),
    //             self.remote_host,
    //             dns_resolution.ttl().num_seconds()
    //         );

    //         self.getdns_resolution_info = Some(dns_resolution);
    //         dns_resolution.ip_addr()
    //     } else {
    //         self.dns_resolution_info
    //             .ok_or("DNS resolution failed!")?
    //             .ip_addr()
    //     };


    //     let remote_addr = SocketAddr::new(remote_addr, self.remote_port);

    //     Ok({
    //         let server = TcpStream::connect(remote_addr)
    //             .await
    //             .expect("Could not create connection");
    //         tracing::debug!(
    //             "Connected client from {:?} to {:?}",
    //             client_addr,
    //             remote_addr
    //         );

    //         let (mut client_read,  mut client_write) = vsock_stream.into_split();
    //         let (mut server_read, mut server_write) = server.into_split();

    //         duplex_forward(&mut client_read, &mut client_write, &mut server_read, &mut server_write, self.desc()).await;
    //         tracing::debug!("VSock Client on {:?} disconnected", client_addr);
    //     })
    // }
    
}
