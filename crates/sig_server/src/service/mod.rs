pub mod attestation_svc;
pub mod authorization_svc;
pub mod auth_registry;
pub mod signing_svc;

#[cfg(debug_assertions)] 
pub mod test_svc;

pub const SIG_HEADER : &str = "x-signature"; // must be lowercase, otherwise server complains!!