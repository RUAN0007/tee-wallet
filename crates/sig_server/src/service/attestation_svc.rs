use tonic::{Request, Response, Status};
use crate::service::attestation_svc::attestation_server::Attestation;

tonic::include_proto!("attestation");

#[derive(Debug, Default)]
pub struct AttestationHandler {}

#[tonic::async_trait]
impl Attestation for AttestationHandler {
    async fn get_attestation_doc(
        &self,
        request: Request<AttestationReq>,
    ) -> Result<Response<AttestationResp>, Status> {
        let reply = AttestationResp {
			doc: "Hello".into(),
			delay_ms: 1,
        };

        Ok(Response::new(reply))
    }
}