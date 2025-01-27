#!/bin/bash

# Check if grpcurl is installed
if ! command -v grpcurl &> /dev/null
then
    echo "grpcurl could not be found. Please install grpcurl and try again."
    exit 1
fi

PROTO_DIR=./crates/sig_server/proto
PROTO_FILE=attestation.proto
REQ="{}"
ADDR="127.0.0.1:7000"

PACK="attestation"
SVC="Attestation"
METHOD="GetAttestationDoc"

grpcurl -plaintext -import-path ${PROTO_DIR} -proto ${PROTO_FILE}  -max-time 10 -d ${REQ} ${ADDR} ${PACK}.${SVC}/${METHOD}

PROTO_FILE=test.proto
REQ='{"host": "example.com", "port": 8080, "timeout_ms": 1000, "msg": "hi, enclave"}'
ADDR="${aws_domain}:9000"
PACK="test"
SVC="Test"
METHOD="ConnectRemoteHost"