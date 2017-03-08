# Gotapdance CLI version

# Build
After [downloading Golang, TD and dependencies:](../README.md)
```
   cd ${GOPATH}/src/github.com/SergeyFrolov/gotapdance/cli
   go build -a .
```

# Usage

Simply run
```
./cli
```
to listen to local connections on default 10500 port.

Then, you'll have a few options:
## Configure HTTP proxy
Now, you will need to ask your particular application(e.g. browser) to proxy connection via 127.0.0.1:10500. There are 2 ways to use TapDance: as a HTTP proxy and as a SOCKS proxy.
  * HTTP Proxy In firefox (both mobile and desktop) I prefer to type ```about:config``` into address line and set the following:

 ```
network.proxy.http_port = 10500
network.proxy.http = 127.0.0.1
network.proxy.ssl_port = 10500
network.proxy.ssl = 127.0.0.1
network.proxy.type = 1
```

 To disable proxying you may simply set ```network.proxy.type``` back to ```5``` or ```0```.

 The same settings are available in GUI: Preferences->Advanced->Network->Settings
## Configure ssh SOCKS proxy
If you have access to some ssh server, say `socksserver`, you can set up ssh SOCKS tunnel.
To set up ssh tunnel, add following to `.ssh/config`:
```ssh
Host socksserver-td
Hostname 123.456.789.012
User cookiemonster
ProxyCommand nc -X connect -x 127.0.0.1:10500 %h %p
```
and run `ssh -D1234 socksserver-td -4`

Then in Firefox just go to Preferences->Advanced->Network->Settings and set SOCKSv5 host to localhost:1234.

## Some utilities use following enivoronment variables: 

 ```bash
export https_proxy=127.0.0.1:10500
export http_proxy=127.0.0.1:10500
wget https://twitter.com
```
Most of the popular utilities also have a flag to specify a proxy.
