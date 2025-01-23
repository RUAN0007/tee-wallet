This crate provides functions to forwards traffic:
* from local vsock port to remote host via tcp
* from local tcp port to remote vsock

The codes for the vsock-to-tcp proxy is copied from (AWS official SDK)[https://github.com/aws/aws-nitro-enclaves-cli/tree/main/vsock_proxy]. It is intended to use at host, to forward the enclave outbound traffic to a remote host. 

We implement the second tcp-to-vsock proxy. It is used in both enclave and host:
* In enclave, forward the outbound tcp traffic to host vsock
  * In enclave, we change the host file to map all external domains to localhost. So all the outbound tcp traffic will first hop to the localhost (enclave), but on the same tcp port. 
  * Then, the traffic is forwarded by the host to remote host by vsock-to-tcp proxy. 
* In host, forward the inbound grpc traffic to enclave vsock