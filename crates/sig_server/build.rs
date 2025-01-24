fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/attestation.proto")?;

    #[cfg(debug_assertions)] 
    tonic_build::compile_protos("proto/test.proto")?;

    Ok(())
}