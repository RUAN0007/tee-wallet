// // Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// // SPDX-License-Identifier: Apache-2.0


#[cfg(target_os = "linux")]
use std::sync::mpsc;

#[cfg(target_os = "linux")]
use proxy::{
    IpAddrType,
    vsock::VSOCK_HOST_CID,
    vsock::VsockProxy,
    tcp::TcpProxy,
};

#[cfg(target_os = "linux")]
use tokio_vsock::{
    VsockStream,
    VsockAddr,
    VsockListener,
};

#[cfg(target_os = "linux")]
use tokio::{
    net::{TcpListener, TcpStream},
    io::{AsyncReadExt, AsyncWriteExt},
};

#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr};

#[cfg(target_os = "linux")]
async fn test_proxy_vsock_to_tcp_connection() {
    // Proxy will translate from port 8000 vsock to localhost port 9000 TCP
    let tcp_port = 9000;
    let vsock_proxy_port = 8000;
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)).to_string();
    let proxy = VsockProxy::new(
        VSOCK_HOST_CID,
        vsock_proxy_port,
        addr,
        tcp_port,
        IpAddrType::IPAddrMixed,
    ).unwrap();
    let proxy = std::sync::Arc::new(proxy);

    let (tx, rx) = mpsc::channel();

    // Create a listening TCP server on port 9000
    let server_handle = tokio::spawn(async move {

		let addr = format!("127.0.0.1:{}", tcp_port);
        
        let server = TcpListener::bind(addr).await.expect("server bind");
        tx.send(true).expect("server send event");
        let (mut stream, _) = server.accept().await.expect("server accept");

        // Read request
        let mut buf = [0; 13];
        stream.read_exact(&mut buf).await.expect("server read");
        let msg = std::str::from_utf8(&buf).expect("from_utf8");
        assert_eq!(msg, "client2server");

        // Write response
        stream.write_all(b"server2client").await.expect("server write");
    });

    let _ret = rx.recv().expect("main recv event");
    let (tx, rx) = mpsc::channel();

    // Start proxy in a different thread
    let listener = proxy.listen().await.expect("proxy listen");
    let proxy_handle = tokio::spawn(async move {
        tx.send(true).expect("proxy send event");
        let _ret = proxy.accept(&listener).await.expect("proxy accept");
    });

    let _ret = rx.recv().expect("main recv event");

    // Start client that connects to proxy on port 8000 vsock
    let client_handle = tokio::spawn(async move {
        let remote_cid = VSOCK_HOST_CID;
        let vsock_addr = VsockAddr::new(remote_cid, vsock_proxy_port);
        let mut vsock_stream = VsockStream::connect(vsock_addr).await.expect("Could not connect");

        // Write request
        vsock_stream.write_all(b"client2server").await.expect("client write");

        // Read response
        let mut buf = [0; 13];

        vsock_stream.read_exact(&mut buf).await.expect("client read");
        let msg = std::str::from_utf8(&buf).expect("from_utf8");
        assert_eq!(msg, "server2client");
    });

    server_handle.await.expect("Server panicked");
    proxy_handle.await.expect("Proxy panicked");
    client_handle.await.expect("Client panicked");
}

#[cfg(target_os = "linux")]
async fn test_proxy_tcp_to_vsock_connection() {
    // Proxy will translate from $TCP_PORT to remote CID 3 port 8000
    let tcp_port = 9000;
    let vsock_proxy_port = 8000;
    let proxy = TcpProxy::new(
        tcp_port,
        VSOCK_HOST_CID,
        vsock_proxy_port,
    ).unwrap();
    let proxy = std::sync::Arc::new(proxy);

    let (tx, rx) = mpsc::channel();

    // Create a listening vsock server on port 8000
    let server_handle = tokio::spawn(async move {

        let sockaddr = VsockAddr::new(VSOCK_HOST_CID, vsock_proxy_port);
        let listener = VsockListener::bind(sockaddr).expect("server bind");
        tx.send(true).expect("server send event");

        let (mut stream, _) = listener.accept().await.expect("server accept");

        // Read request
        let mut buf = [0; 13];
        stream.read_exact(&mut buf).await.expect("server read");
        let msg = std::str::from_utf8(&buf).expect("from_utf8");
        assert_eq!(msg, "client2server");

        // Write response
        stream.write_all(b"server2client").await.expect("server write");
    });

    let _ret = rx.recv().expect("main recv event");
    let (tx, rx) = mpsc::channel();

    // Start proxy in a different thread
    let listener = proxy.listen().await.expect("proxy listen");
    let proxy_handle = tokio::spawn(async move {
        tx.send(true).expect("proxy send event");
        let _ret = proxy.accept(&listener).await.expect("proxy accept");
    });

    let _ret = rx.recv().expect("main recv event");

    let client_handle = tokio::spawn(async move {
		let addr = format!("127.0.0.1:{}", tcp_port);
        let mut stream = TcpStream::connect(addr).await.expect("Could not create connection");

        // Write request
        stream.write_all(b"client2server").await.expect("client write");

        // Read response
        let mut buf = [0; 13];

        stream.read_exact(&mut buf).await.expect("client read");
        let msg = std::str::from_utf8(&buf).expect("from_utf8");
        assert_eq!(msg, "server2client");
    });

    server_handle.await.expect("Server panicked");
    proxy_handle.await.expect("Proxy panicked");
    client_handle.await.expect("Client panicked");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let trace_cfg = trace::TraceConfig { 
        prefix: "proxy".to_owned(), 
        dir: "log".to_owned(), 
        level: tracing::Level::DEBUG, 
        console: true, flame: false };

    let _g = trace::init_tracing(trace_cfg);

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "v2t" {
        test_proxy_vsock_to_tcp_connection().await;
    } else if args.len() > 1 && args[1] == "t2v" {
        test_proxy_tcp_to_vsock_connection().await;
    } else if args.len() > 2 && args[1] == "dns" {
        let host = &args[2];
        let ip = proxy::dns::resolve_single(host, proxy::IpAddrType::IPAddrMixed).await.unwrap();
        println!("Resolved host {} to ip {:?}", host, ip);
    } else if args.len() > 2 && args[1] == "conn" {
        let host = &args[2];
        let tcp_port = 9000;
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", tcp_port)).await.expect("server fail to listen");
        tracing::info!("Echo server listening on port {}", tcp_port);

        let h = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("server fail to listen");
            let (mut reader, mut writer) = socket.split();
            let mut buffer = vec![0; 1024];

            match reader.read(&mut buffer).await {
                Ok(0) => return,
                Ok(n) => {
                    tracing::info!("Received and echo back data {} bytes from client: {:?}", n, &buffer[..n]);
                    if let Err(e) = writer.write_all(&buffer[..n]).await {
                        tracing::error!("Failed to send response: {:?}", e);
                        return;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to read from socket: {:?}", e);
                    return;
                }
            }
        });
        let addr = format!("{}:{}", host, tcp_port);
        tracing::info!("Connecting to {}", addr);
        let mut stream = TcpStream::connect(addr).await.expect("Could not create connection");
        // Write request
        stream.write_all(b"client2server").await.expect("client write");

        h.await.expect("Server panicked");
    } else {
        panic!("Invalid arguments {:?}", args);
    }
}

#[cfg(not(target_os = "linux"))]
#[tokio::main]
async fn main() {
    panic!("This test only runs on Linux");
}