# Build
1) Install [][https://golang.org/dl/] (tested against 1.7 versions), set GOPATH:
GOPATH="${HOME}/go/"
2) 
   go get github.com/SergeyFrolov/gotapdance github.com/Sirupsen/logrus github.com/agl/ed25519/extra25519 github.com/zmap/zgrab/ztools/x509 github.com/zmap/zgrab/ztools/ztls golang.org/x/crypto/curve25519 golang.org/x/mobile/cmd/gomobile
   
2a) If needed gomobile: 
   gomobile init
3) cd ${GOPATH}/src/github.com/SergeyFrolov/gotapdance
4a) cd cli
    go build .
4b) cd gui
    go build .
4c) # to build and install on USB-connected developer-enabled android phone
    ./build_install.sh
