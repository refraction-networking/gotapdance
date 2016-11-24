TARGET="android"
NAME='gui'
rm ${NAME}.apk
gomobile install -target $TARGET -o ${NAME}.apk gitlab.decoyrouting.com/decoy/tapdance/gotapdance/gui
#gomobile install -target $TARGET gitlab.decoyrouting.com/decoy/tapdance/gotapdance/gui
