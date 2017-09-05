## Get gomobile
You'd need [gomobile](https://godoc.org/golang.org/x/mobile/cmd/gomobile) to compile GUI version:
 ```bash
 go get golang.org/x/mobile/cmd/gomobile
 gomobile init
```

##  Wrapper
### To simply build proxybind.aar library for Android:
```
  cd ${GOPATH}/src/github.com/SergeyFrolov/gotapdance/proxybind
  gomobile bind -target=android
```
### Gradle Plugin
For convinience it is recommended to use [Gobind gradle plugin](https://godoc.org/golang.org/x/mobile/cmd/gomobile#hdr-Gobind_gradle_plugin), compatible with Android Studio.
