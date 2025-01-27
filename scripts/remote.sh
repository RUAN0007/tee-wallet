aws_host="ec2-user@ubuntu@ec2-52-62-132-168.ap-southeast-2.compute.amazonaws.com"

aws_host="ec2-user@ec2-52-65-66-36.ap-southeast-2.compute.amazonaws.com"

pem="../tee_wallet_aws.pem"

ssh -i ${pem} ${aws_host}
scp -i ${pem} ../target/x86_64-unknown-linux-gnu/debug/proxy ${aws_host}:proxy
scp -i ${pem} ../target/x86_64-unknown-linux-gnu/debug/sig_server ${aws_host}:sig_server
scp -i ${pem} ../crates/sig_server/config/default.toml ${aws_host}:default.toml
scp -i ${pem} ./Dockerfile ${aws_host}:Dockerfile 

scp -i ${pem} ./run.sh ${aws_host}:run.sh

echo "hi, world" | nc ${aws_host} 9000


# run in ec2
docker build -t sig_server -f Dockerfile .
nitro-cli build-enclave --docker-uri sig_server:latest --output-file sig_server.eif

# Start building the Enclave Image...
# Using the locally available Docker image...
# Enclave Image successfully created.
# {
#   "Measurements": {
#     "HashAlgorithm": "Sha384 { ... }",
#     "PCR0": "adabdd77b42f6e0a21165fca639f2d7305acf732210bbb15d4402e3221550779f92c989efa9bec68aa4d3671c66110a5",
#     "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
#     "PCR2": "54965aba581b1993c89ee3656090eb59e27e8b65ebbbe58591ad19284ae6714464ec3ba6fa0021650a15946201accfef"
#   }
# }

ENCLAVE_CID=10
nitro-cli run-enclave --cpu-count 2 --memory 8192 --enclave-cid ${ENCLAVE_CID} --eif-path sig_server.eif --debug-mode --attach-console

ENCLAVE_ID=$(nitro-cli describe-enclaves | jq ".[]|select(.EnclaveCID==${ENCLAVE_CID})" | jq -r ".EnclaveID")

nitro-cli console --enclave-id ${ENCLAVE_ID}

nitro-cli terminate-enclave --enclave-id ${ENCLAVE_ID}
