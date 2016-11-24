# Build
0) Install [Golang](https://golang.org/dl/) (tested against 1.7 versions), set GOPATH:
```
 GOPATH="${HOME}/go/"
```
1) Get source code for Go Tapdance and all dependencies:
```
 go get github.com/SergeyFrolov/gotapdance github.com/Sirupsen/logrus \
   github.com/agl/ed25519/extra25519 github.com/zmap/zgrab/ztools/x509 \
   github.com/zmap/zgrab/ztools/ztls golang.org/x/crypto/curve25519 \
   golang.org/x/mobile/cmd/gomobile  
```
1a) If gomobile is needed(e.g. non-CLI version):
```
 ${GOPATH}/bin/gomobile init
```
2) There are 3 versions to build:

   [Command Line Interface](cli)
   
   [Golang Mobile Bindings](proxybind) – to use as a library in native apps, written in Java/ObjC for Android or iOS.
  
   [Pure Golang cross-platform GUI](gui) – ugly, but the same code compiles virtually everywhere (tested on Ubuntu and Android, but supposed to work on iOS and Windows PC as well)
