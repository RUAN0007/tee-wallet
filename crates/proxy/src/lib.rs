
#[cfg(target_os = "linux")]
pub mod vsock;
#[cfg(target_os = "linux")]
pub mod tcp;

pub mod tcp2tcp;

pub mod dns;

pub mod config;

mod traffic;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum IpAddrType {
    /// Only allows IP4 addresses
    IPAddrV4Only,
    /// Only allows IP6 addresses
    IPAddrV6Only,
    /// Allows both IP4 and IP6 addresses
    IPAddrMixed,
}

/// The most common result type provided by VsockProxy operations.
pub type ProxyResult<T> = Result<T, String>;