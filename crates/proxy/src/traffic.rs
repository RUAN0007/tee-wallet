
use nix::sys::select::{select, FdSet};
use std::io::{Read, Write};

const BUFF_SIZE: usize = 8192;

pub fn duplex_forward<C, S>(client_socket: i32, server_socket: i32, client: &mut C, server: &mut S) where C: Read + Write, 
S: Read + Write {
    let mut disconnected = false;
    while !disconnected {
        let mut set = FdSet::new();
        set.insert(client_socket);
        set.insert(server_socket);

        select(None, Some(&mut set), None, None, None).expect("select");

        if set.contains(client_socket) {
            disconnected = forward(client, server);
        }
        if set.contains(server_socket) {
            disconnected = forward( server, client);
        }
    }
}

/// Transfers a chunck of maximum 4KB from src to dst
/// If no error occurs, returns true if the source disconnects and false otherwise
fn forward(src: &mut dyn Read, dst: &mut dyn Write) -> bool {
    let mut buffer = [0u8; BUFF_SIZE];

    let nbytes = src.read(&mut buffer);
    let nbytes = nbytes.unwrap_or(0);

    if nbytes == 0 {
        return true;
    }

    dst.write_all(&buffer[..nbytes]).is_err()
}

#[cfg(test)]
mod tests {
    use rand;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::process::Command;

    use super::*;

    /// Test transfer function with more data than buffer
    #[test]
    fn test_transfer() {
        let data: Vec<u8> = (0..2 * BUFF_SIZE).map(|_| rand::random::<u8>()).collect();

        let _ret = fs::create_dir("tmp");
        let mut src = File::create("tmp/src").unwrap();
        let mut dst = File::create("tmp/dst").unwrap();

        let _ret = src.write_all(&data);

        let mut src = File::open("tmp/src").unwrap();
        while !forward(&mut src, &mut dst) {}

        let status = Command::new("cmp")
            .arg("tmp/src")
            .arg("tmp/dst")
            .status()
            .expect("command");

        let _ret = fs::remove_dir_all("tmp");

        assert!(status.success());
    }
}