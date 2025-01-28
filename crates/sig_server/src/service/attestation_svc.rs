
use rsa::pkcs1::EncodeRsaPublicKey;
use tonic::{Request, Response, Status};
use crate::service::attestation_svc::attestation_server::Attestation;
use crate::enclave;
use crate::errors;

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

        let _start_time = Instant::now(); 

        let ctx = nsm_init();

        if ctx == 0 {
            return Err(Status::internal("NSM initialization failed"));
        }
        let user_data = Some(ByteBuf::from("GET_ATTESTATION_DOC"));
        let nonce = Some(ByteBuf::from(request.get_ref().nonce.clone()));

        let pk = Some(ByteBuf::from(enclave::RSA_KEYPAIR.1.to_pkcs1_der().unwrap().as_bytes()));

        let response = nsm_process_request(
            ctx,
            NsmReq::Attestation {
                user_data: user_data.clone(),
                nonce: nonce.clone(),
                public_key: pk.clone(),
            },
        );
        nsm_exit(ctx);
        let mut _duration = std::time::Duration::default();

        #[cfg(debug_assertions)]
        {
            _duration = _start_time.elapsed();
        }


        match response {
            NsmResp::Attestation { document } => {
                if document.is_empty() {
                    return Err(Status::internal(errors::ERR_EMPTY_ATTESTATION_DOC));
                }

                let reply = AttestationResp {
                    doc: document.into(),
                    delay_ms: _duration.as_millis() as u64,
                };

                Ok(Response::new(reply))
            }
            #[cfg(any(target_os = "linux", not(debug_assertions)))]            
            e => {
                Err(Status::internal(format!("invalid response from NSM, {:?}", e)))
            }
            #[cfg(all(not(target_os = "linux"), debug_assertions))]            
            e => {
                tracing::warn!("NSM is not available ({:?}), using fake attestation document for local debugging", e);
                let reply = AttestationResp {
                    doc: hex::decode(FAKE_DOC).unwrap(),
                    delay_ms: 0,
                };

                Ok(Response::new(reply))
            }

        }
    }
}

// this attestation document is generated by the enclave, and is used for local debugging purpose. The document corresponds to the fixed keypair in enclave.rs, when target is not linux and in debug mode.
#[cfg(all(not(target_os = "linux"), debug_assertions))]            
const FAKE_DOC : &str ="8444a1013822a0591257a9696d6f64756c655f69647827692d30643531663966643963353936616366342d656e633031393461626438326463633638346366646967657374665348413338346974696d657374616d701b00000194abd95f066470637273b000583000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001583000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002583000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003583000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004583061f9772fca6156e6cac0f852986d84ea1731c10ae834929ac5f8a2bbd5617e1e2572f8effb877fa5c374e5595dc0c4450558300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000658300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000758300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000858300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000958300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b636572746966696361746559028a308202863082020ba00302010202100194abd82dcc684c0000000067988991300a06082a8648ce3d040303308193310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313e303c06035504030c35692d30643531663966643963353936616366342e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c61766573301e170d3235303132383037333835345a170d3235303132383130333835375a308198310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533143304106035504030c3a692d30643531663966643963353936616366342d656e63303139346162643832646363363834632e61702d736f757468656173742d322e6177733076301006072a8648ce3d020106052b8104002203620004c1ead0ed478ac44b184c5cd2d2aee63edc8f78ccde249c228657e7f5bd2d209dfa3ab571773d7bdd2c4ee58ad6af0f77ca7399538fe78021deb87fee82f1e33121dd6c560c307b57d899abeb406464b75027ef0eab1d9417af9d09c99bb38e26a31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0300a06082a8648ce3d040303036900306602310096166008667884982db947f975b9c922e4582268ec81ffd3cce455588fe2be97b4cc8741d11bfe0468d59ff84bb9158f0231009e0a4dd0d6312075c48ddc13a1a13695ad87db799f41b3268e5c7b386ebcde1218fe4272cbc1b40abc5a67a954e0774868636162756e646c65845902153082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff65902c8308202c43082024aa003020102021100b51d7c1353a5e170a7bdd3df8d7241da300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3235303132373030343834375a170d3235303231363031343834375a3069310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313b303906035504030c32313564623662396132353938663337362e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004847cbdf7332499a10c86fc1a09f77c050a14b7a15210ca73a109f12fc9f6a6ee46d17ce53863fd0718f72c746a207357d74909bd9f237f2b8883c1f58ae1b1fb52a348bf68dcfbaa27431b2a90d9d3bdaf12cbdccb3adda9ed68d45fe55fd6a0a381d53081d230120603551d130101ff040830060101ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf99a9df4b96301d0603551d0e041604141bbfcee0c3a56c0fdb3c8e5a47ca96eed19e997a300e0603551d0f0101ff040403020186306c0603551d1f046530633061a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d63726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632d376436332d343262642d396539662d3539333338636236376638342e63726c300a06082a8648ce3d0403030368003065023100f27aedf4ec1e354c63bd01d404c2d0b7f20c80ec51edbfc41ed75eca5efbc9f9d3a8f62d8bf8b55813c9280f5dd3c1fb0230035c2cfb72e4bdcb7f4bc7a1f56b93214c67697ee774aa9d289d83aea00a47832629944d913c2f73dff6abd6d00cedd459032f3082032b308202b1a003020102021100e35e1be90b861c6a4e87aa48a4b3031d300a06082a8648ce3d0403033069310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313b303906035504030c32313564623662396132353938663337362e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c61766573301e170d3235303132383035303531395a170d3235303230323231303531385a30818e3141303f06035504030c38383665363532393130323962366339332e7a6f6e616c2e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c653076301006072a8648ce3d020106052b810400220362000485ffc156ff55eabf0aff49ff3f244729e811a07d83aac83d49770e03e19ff43b0ba72a86ab1db519ed758a0450b8de664272c0fc13c055cab32b3025848173f465a5a270cbed932c3dbea493928bbc5b1890896067a43879621e8adb60e05531a381f63081f330120603551d130101ff040830060101ff020101301f0603551d230418301680141bbfcee0c3a56c0fdb3c8e5a47ca96eed19e997a301d0603551d0e04160414a17f1b16c72b0ddca55d0da447f6ed617d1027b2300e0603551d0f0101ff04040302018630818c0603551d1f048184308181307fa07da07b8679687474703a2f2f63726c2d61702d736f757468656173742d322d6177732d6e6974726f2d656e636c617665732e73332e61702d736f757468656173742d322e616d617a6f6e6177732e636f6d2f63726c2f63313234393238372d383661372d343731632d613235342d3838616234633631333835382e63726c300a06082a8648ce3d0403030368003065023100c273e8cf37e526d2464b22f78574fd91af7b65670566f5f18f1eb83232ae4a2eae37702152fadcbab7a2c38aca13536a023033d422f7b204bdf9d8a87de3b3a559d8febe21c289bd927cb83dcb01d99e853352a3805985e1fd4b8ec9b803d3cd29ed5902cd308202c93082024fa003020102021500ee894eda92dde11b52992a53e31de95bf77c036d300a06082a8648ce3d04030330818e3141303f06035504030c38383665363532393130323962366339332e7a6f6e616c2e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c65301e170d3235303132383037333331395a170d3235303132393037333331395a308193310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313e303c06035504030c35692d30643531663966643963353936616366342e61702d736f757468656173742d322e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004e5f7f5f57749a26dd00b84024b628a010a03054c8a642e22241f122777974e92f8bdb95a038a1343c71e19f11d7e83e12bbce11844734fea2ed661fe7820af5bf0bf8fb76af56e77d3cc7a94b4a259d4a9959e6bf9be96150f403c68c64e95fda366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020204301d0603551d0e041604145034f1100f496dbe94b3af7e6367f7a533809069301f0603551d23041830168014a17f1b16c72b0ddca55d0da447f6ed617d1027b2300a06082a8648ce3d0403030368003065023100eacb10d59205c986bc43bcc6efcdcabb5c70c0a0fbe4ed2a07ef7770de0d9006f73ccf42deddc6cf40edf684033cd34f023016441d6f26f464749fc8bd2ccc5ae784b0c5c50c0798296ed8bfc4f554a35fa0d95d60fd64936eb2a51fbf4ff4c8aba46a7075626c69635f6b657959010e3082010a0282010100bca7c71fff29eb2f0ef1fe31b662109255e9705c2ee01a8fb01c9acd55ad78fd5d1d78f9093860fc7956a4539d011e1fe3e8fc3da4e9fb7808487a74ce876c42318fe5c2b51319107086b1591e6517a29faa5cab8e61d77655a3b4df52f1779a6e77bedb18bffe2300c97ca3ac9f2504a874eaf44919796ea0bc37fba7af63a9596ad5c6a01e6e82ad5d0afc6647322303c9a65260908afede219bdb2080770e52045fb05a74d3a59123f47a8dd91366e2ea75c6de822bc97a023b77c2691da42bbf279882493190aefe11d8bfc160fae5d859af0e3a8d2e516fa4cc36a59eae718b4da0ac10abc49cc7cfa8be55996938aaef9e2b74ddfd61bcfd3f29631e0b020301000169757365725f64617461534745545f4154544553544154494f4e5f444f43656e6f6e636543010203586039c4251c5382b00ebfb651be6accfc86f280300c0223b9b8d926bbc084b8107009e90221bd90b0aa1ae94c71187ae8380d1c123fb4d27db84f004f26ec313c52fcdfd4978739718f123e9d0e2a84577b3450ea4ef9588deab4b7bb710881f247";