[![Build Status](https://travis-ci.org/sergeyfrolov/gotapdance.svg?branch=master)
# Build
## Download Golang and TapDance and dependencies
1. Install [Golang](https://golang.org/dl/) (tested against 1.7 versions), set GOPATH:

 ```bash
GOPATH="${HOME}/go/"
```

2. Get source code for Go Tapdance and all dependencies:

 ```bash
go get github.com/SergeyFrolov/gotapdance github.com/Sirupsen/logrus \
           github.com/agl/ed25519/extra25519 github.com/zmap/zcrypto/x509 \
           github.com/zmap/zcrypto/tls golang.org/x/crypto/curve25519 \
           golang.org/x/mobile/cmd/gomobile github.com/golang/protobuf/proto
```
Ignore the "no buildable Go source files" warning.

If you have outdated versions of libraries above you might want to do `go get -u all`

## Build specific version

 There are 3 versions of TapDance client:

 * [Command Line Interface](cli)

 * Mobile: native applications in Java/Objective C for Android or iOS. Golang bindings are used as a shared library.

   * [Android application in Java](android)
    
   * iOS version: coming ~~soon~~ eventually

   * [Golang Bindings](proxybind)

 * [Pure Golang cross-platform GUI](gui) – ugly, not maintaed, lives as PoC. This code compiles virtually everywhere (tested on Ubuntu and Android, but supposed to work on iOS and Windows PC as well)

