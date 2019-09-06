PACKAGE="github.com/refraction-networking/gotapdance/tdproxy"
RFILE="$GOPATH/src/$PACKAGE/README.md"
godoc2ghmd $PACKAGE > $RFILE

