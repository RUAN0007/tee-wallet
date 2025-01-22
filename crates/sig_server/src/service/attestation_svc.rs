use tonic::{Request, Response, Status};
use crate::service::attestation_svc::attestation_server::Attestation;

use aws_nitro_enclaves_nsm_api::api::{Request as NsmReq, Response as NsmResp};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;
use std::time::Instant;

tonic::include_proto!("attestation");

#[derive(Debug, Default)]
pub struct AttestationHandler {}
#[tonic::async_trait]
impl Attestation for AttestationHandler {
    async fn get_attestation_doc(
        &self,
        request: Request<AttestationReq>,
    ) -> Result<Response<AttestationResp>, Status> {

        let start_time = Instant::now(); 
        let ctx = nsm_init();
        if ctx == 0 {
            return Err(Status::internal("NSM initialization failed"));
        }
        let user_data = Some(ByteBuf::from("GET_ATTESTATION_DOC"));
        let nonce = Some(ByteBuf::from(request.get_ref().nonce.clone()));
        let public_key = user_data.clone(); // TODO: 

        let response = nsm_process_request(
            ctx,
            NsmReq::Attestation {
                user_data,
                nonce,
                public_key,
            },
        );
        nsm_exit(ctx);
        let duration = start_time.elapsed();

        match response {
            NsmResp::Attestation { document } => {
                if document.is_empty() {
                    return Err(Status::internal("Attestation document is empty"));
                }

                let reply = AttestationResp {
                    doc: document.into(),
                    delay_ms: duration.as_millis() as u64,
                };

                Ok(Response::new(reply))
            }
            _ => {
                return Err(Status::internal("Invalid response from NSM"));
            }
        }
    }
}