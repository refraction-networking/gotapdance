<p align="center">
<a href="https://refraction.network"><img src="https://user-images.githubusercontent.com/5443147/30133006-7c3019f4-930f-11e7-9f60-3df45ee13d9d.png" alt="refract"></a>
<h1 class="header-title" align="center">TapDance Client</h1>

<p align="center">TapDance is a free-to-use anti-censorship technology, protected from enumeration attacks.</p>
<p align="center">
<a href="https://travis-ci.org/sergeyfrolov/gotapdance"><img src="https://travis-ci.org/sergeyfrolov/gotapdance.svg?label=build"></a>
<a href="https://godoc.org/github.com/sergeyfrolov/gotapdance/tapdance"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
	<a href="https://goreportcard.com/report/github.com/sergeyfrolov/gotapdance"><img src="https://goreportcard.com/badge/github.com/sergeyfrolov/gotapdance"></a>
</p>

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
 
 # Links
 
 [Refraction Networking](https://refraction.network) is an umberlla term for the family of similarly working technnologies.
 
 TapDance station code released for FOCI'17 on github: [refraction-networking/tapdance](https://github.com/refraction-networking/tapdance) 
 
 Original 2014 paper: ["TapDance: End-to-Middle Anticensorship without Flow Blocking"](https://ericw.us/trow/tapdance-sec14.pdf)
 
 Newer(2017) paper that shows TapDance working at high-scale: ["An ISP-Scale Deployment of TapDance"](https://sfrolov.io/papers/foci17-paper-frolov_0.pdf)
