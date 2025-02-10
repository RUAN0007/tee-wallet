TBD

* prepare linux building environment
```
docker build --platform linux/amd64 -t rust-build-env scripts/build
```

* To build for linux target
```
docker run --platform linux/amd64 -it --rm -v $(pwd):/usr/app -w /usr/app --entrypoint /bin/bash rust-build-env -c 'cargo build --target x86_64-unknown-linux-gnu'
```
