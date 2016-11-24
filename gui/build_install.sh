TARGET="android"
NAME='gui'
rm ${NAME}.apk
gomobile install -target $TARGET -o ${NAME}.apk github.com/SergeyFrolov/gotapdance/gui
