# Build
1. Install [Golang](https://golang.org/dl/) (tested against 1.7 versions), set GOPATH:

 ```bash
GOPATH="${HOME}/go/"
```
2. Get source code for Go Tapdance and all dependencies:

 ```bash
go get github.com/SergeyFrolov/gotapdance github.com/Sirupsen/logrus \
           github.com/agl/ed25519/extra25519 github.com/zmap/zgrab/ztools/x509 \
           github.com/zmap/zgrab/ztools/ztls golang.org/x/crypto/curve25519 \
           golang.org/x/mobile/cmd/gomobile  
```
3. If gomobile is needed(e.g. non-CLI version):

 ```bash
${GOPATH}/bin/gomobile init
```
4. There are 3 versions:

  * [Command Line Interface](cli)

  * Mobile: Native applications in Java/Objective C for Android or iOS. Golang bindings are used as a shared library.

    * [Android application in Java](android)
    
    * iOS version: coming ~~soon~~ eventually

    * [Golang Bindings](proxybind)

  * [Pure Golang cross-platform GUI](gui) – ugly, but the same code compiles virtually everywhere (tested on Ubuntu and Android, but supposed to work on iOS and Windows PC as well)
