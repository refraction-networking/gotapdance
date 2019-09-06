## Note
This code is for previous version of TapDance Android app, which doesn't create VPN for the whole phone, but merely binds proxy to a certain port. It still could be used in this mode by configuring apps(e.g. Firefox) to use local proxy on said port, however usability is quite limited and we consider this app to be Proof of Concept.

There is a plan to develop a new version of app, that would actually proxy all traffic.

## Get gomobile
You'd need [gomobile](https://godoc.org/golang.org/x/mobile/cmd/gomobile) to compile GUI version:
 ```bash
 go get golang.org/x/mobile/cmd/gomobile
 gomobile init
```

##  Wrapper
### To simply build proxybind.aar library for Android:
```
  cd ${GOPATH}/src/github.com/refraction-networking/gotapdance/gobind
  gomobile bind -target=android
```
### Gradle Plugin
For convinience it is recommended to use [Gobind gradle plugin](https://godoc.org/golang.org/x/mobile/cmd/gomobile#hdr-Gobind_gradle_plugin), compatible with Android Studio.
