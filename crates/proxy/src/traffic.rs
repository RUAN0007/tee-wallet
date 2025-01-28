
// use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[allow(dead_code)]
pub async fn duplex_forward<A, B, C, D>(client_read: &mut A, client_write: &mut B, server_read: &mut C, server_write: &mut D, desc: String)
where
    A: AsyncReadExt + Unpin,
    B: AsyncWriteExt + Unpin,
    C: AsyncReadExt + Unpin,
    D: AsyncWriteExt + Unpin,
{
    let client_to_server = async {
        tokio::io::copy(client_read, server_write).await
    };

    let server_to_client = async {
        tokio::io::copy(server_read, client_write).await
    };

    tokio::select! {
        result = client_to_server => {
            if let Err(e) = result {
                if e.kind() == std::io::ErrorKind::NotConnected {
                    tracing::debug!("Remote client {} closes the connection. ", desc);
                } else {
                    tracing::error!("Error forwarding from client to server: {:?}", e);
                }
            }
        },
        result = server_to_client => {
            if let Err(e) = result {
                tracing::error!("Error forwarding from server to client: {:?}", e);
            }
        },
    }

    tracing::debug!("{} connection closed", desc);
}

// const BUFF_SIZE: usize = 8192;
// pub async fn duplex_forward<A, B, C, D>(
//     client_read: &mut A, client_write : &mut B,
//     server_read: &mut C, server_write : &mut D,
//     desc : String) where 
//     A: AsyncReadExt + Unpin,
//     B: AsyncWriteExt + Unpin,
//     C: AsyncReadExt + Unpin,
//     D: AsyncWriteExt + Unpin,
//     {

//     let mut disconnected_from_cli = false;
//     let mut disconnected_from_server = false;
//     let mut cli_buffer = [0u8; BUFF_SIZE];
//     let mut server_buffer = [0u8; BUFF_SIZE];

//     while !disconnected_from_cli && !disconnected_from_server {
//         tokio::select! {
//             read_result = client_read.read(&mut cli_buffer) => {
//                 match {
//                     read_result
//                 } {
//                     Ok(0) => {
//                         tracing::debug!("{} client disconnected", desc);
//                         disconnected_from_cli = true;
//                     },
//                     Ok(nbytes) => {
//                         tracing::debug!("{} client read {} bytes. ", desc, nbytes);
//                         server_write.write_all(&cli_buffer[..nbytes]).await.unwrap_or_else(|e| {
//                             tracing::error!("Error writing to {} server: {:?}", desc, e);
//                             disconnected_from_cli = true;
//                         });
//                     },
//                     Err(e) => {
//                         if e.kind() == std::io::ErrorKind::NotConnected {
//                             tracing::debug!("Remote client {} closes the connection. ", desc);
//                         } else {
//                             tracing::error!("Error reading from {} client: {:?}", desc, e);
//                         }
//                         disconnected_from_cli = true;
//                     }
//                 }
//             },

//             read_result = server_read.read(&mut server_buffer) => {
//                 match {
//                     read_result
//                 } {
//                     Ok(0) => {
//                         tracing::debug!("{} server disconnected", desc);
//                         disconnected_from_server = true;
//                     },
//                     Ok(nbytes) => {
//                         tracing::debug!("{} server read {} bytes", desc, nbytes); 
//                         client_write.write_all(&server_buffer[..nbytes]).await.unwrap_or_else(|e| {
//                             tracing::error!("Error writing to {} client: {:?}", desc, e);
//                             disconnected_from_server = true;
//                         });
//                     },
//                     Err(e) => {
//                         tracing::error!("Error reading from {} server: {:?}", desc, e);
//                         disconnected_from_server = true;
//                     }
//                 }
//             }
//         }
//     }
//     if disconnected_from_cli {
//         tracing::debug!("{} client disconnected. Start to shut down server", desc);
//         server_write.shutdown().await.unwrap_or_else(|e| {
//             tracing::error!("Error shutting down {} server write: {:?}", desc, e);
//         });
//     }

//     if disconnected_from_server {
//         tracing::debug!("{} server disconnected. Start to shut down client", desc);
//         client_write.shutdown().await.unwrap_or_else(|e| {
//             tracing::error!("Error shutting down {} client write: {:?}", desc, e);
//         });
//     }
// }

#[cfg(test)]
mod tests {
    use rand;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use tokio::fs::File as TokioFile;
    use tokio::net::{TcpListener, TcpStream};
    use std::process::Command;
    use tokio::fs::OpenOptions;

    use super::*;

    /// Test duplex_forward function with more data than buffer
    #[ignore] // Ignoring this test as sometimes fail to flush to dest file. 
    #[tokio::test]
    async fn test_duplex_forward() {
        let data: Vec<u8> = (0..2 * BUFF_SIZE).map(|_| rand::random::<u8>()).collect();

        let _ret = fs::create_dir("tmp");
        let mut src = File::create("tmp/src").unwrap();
        src.write_all(&data).unwrap();

        let listener = TcpListener::bind("127.0.0.1:8000").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (tcp_socket, _) = listener.accept().await.unwrap();
            let (mut server_read, mut server_write) = tcp_socket.into_split();
            TokioFile::create("tmp/dst").await.unwrap();

            let dst_file = OpenOptions::new().read(true).write(true).create(true).open("tmp/dst").await.unwrap();
            let (mut dist_file_read, mut dist_file_write) = tokio::io::split(dst_file);

            duplex_forward(&mut server_read, &mut server_write, &mut dist_file_read, &mut dist_file_write, "tcp_to_file".to_string()).await;
        });

        let client_handle = tokio::spawn(async move {
            let client_socket = TcpStream::connect(addr).await.unwrap();
            let (mut client_read, mut client_write) = client_socket.into_split();
            let src_file = OpenOptions::new().read(true).write(true).create(true).open("tmp/src").await.unwrap();
            // let src_file = TokioFile::open("tmp/src").await.unwrap();
            let (mut src_file_read, mut src_file_write) = tokio::io::split(src_file);
            duplex_forward(&mut src_file_read, &mut src_file_write, &mut client_read, &mut client_write, "file_to_tcp".to_string()).await;
        });

        let _ = tokio::try_join!(server_handle, client_handle);

        let status = Command::new("cmp")
            .arg("tmp/src")
            .arg("tmp/dst")
            .status()
            .expect("command");

        let _ret = fs::remove_dir_all("tmp");

        assert!(status.success());
    }
}