## Install egl libraries:
On Ubuntu:
```
sudo apt-get install libegl1-mesa-dev libgles2-mesa-dev libx11-dev
```

## Get gomobile
You'd need [gomobile](https://godoc.org/golang.org/x/mobile/cmd/gomobile) to compile GUI version:
 ```bash
 go get golang.org/x/mobile/cmd/gomobile
 gomobile init
```

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

# Ugly Screenshot
Pure Golang version is not being worked on at all, remains here just as a Proof of Concept.

<img src="https://cloud.githubusercontent.com/assets/5443147/20784804/e2f3e388-b759-11e6-851b-e12caa759715.jpg" width="320">
