use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::str;
use std::sync::mpsc;
use std::thread;
use vsock::{VsockAddr, VsockListener};

use proxy::{tcp::TcpProxy, vsock::VSOCK_HOST_CID};

const TCP_PORT: u16 = 9000;
const VSOCK_PORT : u32 = 8000;

/// Test connection with both client and server sending each other messages
#[test]
fn test_proxy_tcp_to_vsock_connection() {
    // Proxy will translate from $TCP_PORT to remote CID 3 port 8000
    let mut proxy = TcpProxy::new(
        TCP_PORT,
        VSOCK_HOST_CID,
        VSOCK_PORT,
        2,
    )
    .unwrap();

    let (tx, rx) = mpsc::channel();

    // Create a listening vsock server on port 8000
    let server_handle = thread::spawn(move || {

        let sockaddr = VsockAddr::new(VSOCK_HOST_CID, VSOCK_PORT);
        let listener = VsockListener::bind(&sockaddr).expect("server bind");
        tx.send(true).expect("server send event");

        let (mut stream, _) = listener.accept().expect("server accept");

        // Read request
        let mut buf = [0; 13];
        stream.read_exact(&mut buf).expect("server read");
        let msg = str::from_utf8(&buf).expect("from_utf8");
        assert_eq!(msg, "client2server");

        // Write response
        stream.write_all(b"server2client").expect("server write");
    });

    let _ret = rx.recv().expect("main recv event");
    let (tx, rx) = mpsc::channel();

    // Start proxy in a different thread
    let listener = proxy.listen().expect("proxy listen");
    let proxy_handle = thread::spawn(move || {
        tx.send(true).expect("proxy send event");
        let _ret = proxy.accept(&listener).expect("proxy accept");
    });

    let _ret = rx.recv().expect("main recv event");

    let client_handle = thread::spawn(move || {
        let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), TCP_PORT);
        let mut stream = TcpStream::connect(localhost).expect("Could not create connection");

        // Write request
        stream.write_all(b"client2server").expect("client write");

        // Read response
        let mut buf = [0; 13];

        stream.read_exact(&mut buf).expect("client read");
        let msg = str::from_utf8(&buf).expect("from_utf8");
        assert_eq!(msg, "server2client");
    });

    server_handle.join().expect("Server panicked");
    proxy_handle.join().expect("Proxy panicked");
    client_handle.join().expect("Client panicked");
}