## Build Android
Make sure you initialized gomobile, installed adb and plugged in your phone.
To test if your plugged phone is visible to adb you may use
```
  adb logcat
```
To install on plugged in Android phone:
```
gomobile install -target android -o gui.apk github.com/SergeyFrolov/gotapdance/gui
```
## Build PC
```
  cd ${GOPATH}/src/github.com/SergeyFrolov/gotapdance/gui
  go build -a
  ./gui
```
## Build iOS
Not tested yet.
