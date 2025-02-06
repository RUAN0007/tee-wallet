fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/attestation.proto")?;
    tonic_build::compile_protos("proto/signing.proto")?;
    tonic_build::compile_protos("proto/authorization.proto")?;

    #[cfg(debug_assertions)] 
    tonic_build::compile_protos("proto/test.proto")?;

    Ok(())
}