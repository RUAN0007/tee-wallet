FROM amazonlinux

RUN yum groupinstall -y "Development Tools"
RUN yum install -y openssl-devel perl-IPC-Cmd perl-FindBin protobuf-compiler protobuf-devel
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.79.0
ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustup target add x86_64-unknown-linux-gnu

RUN chmod +x /root/.cargo/bin/cargo

ENTRYPOINT [ "/bin/bash", "-l", "-c" ]