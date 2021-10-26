FROM golang:1.16

RUN apt-get update
RUN apt-get install tmux git wget

WORKDIR /go/src/github/refracction-networking/gotapdance
COPY . .

RUN go mod init "github.com/refraction-networking/gotapdance"
RUN go mod tidy
RUN go get -d -v ./...
RUN go install -v ./...

# no run / entrypoint specified. this containter is meant to be run w/
# gns3 and connected to using terminal or telnet.
