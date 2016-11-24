##  Wrapper
### To simply build proxybind.aar library for Android:
```
  cd ${GOPATH}/src/github.com/SergeyFrolov/gotapdance/proxybind
  gomobile bind -target=android
```
### Gradle Plugin
For convinience it is recommended to use [Gobind gradle plugin](https://godoc.org/golang.org/x/mobile/cmd/gomobile#hdr-Gobind_gradle_plugin), compatible with Android Studio.
