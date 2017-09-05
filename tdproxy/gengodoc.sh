PACKAGE="github.com/SergeyFrolov/gotapdance/tdproxy"
RFILE="$GOPATH/src/$PACKAGE/README.md"
godoc2ghmd $PACKAGE > $RFILE

