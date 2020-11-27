# Gotapdance CLI version

## Build

After [downloading Golang, TD and dependencies:](../README.md)

```sh
   cd ${GOPATH:-~/go}/src/github.com/refraction-networking/gotapdance/cli # works even if GOPATH is not set
   go build -a .
```

## Usage

Simply run
```txt
$./cli -connect-addr=<decoy_address> [OPTIONS]

Options:
  -api-endpoint string
        If set, API endpoint to use when performing API registration. If not set, uses decoy registration.
  -assetsdir string
        Folder to read assets from. (default "./assets/")
  -connect-addr string
        If set, tapdance will transparently connect to provided address, which must be either hostname:port or ip:port. Default(unset): connects client to forwardproxy, to which CONNECT request is yet to be written.
  -debug
        Enable debug level logs
  -decoy string
        Sets single decoy. ClientConf won't be requested. Accepts "SNI,IP" or simply "SNI" — IP will be resolved. Examples: "site.io,1.2.3.4", "site.io"
  -disable-ipv6
        Explicitly disable IPv6 decoys. Default(false): enable IPv6 only if interface with global IPv6 address is available.
  -obfs4-distBias
        Enable obfs4 using ScrambleSuit style table generation
  -port int
        The refraction client will listen for connections on this port. (default 10500)
  -proxy
        Send the proxy header with all packets from station to covert host
  -td
        Enable tapdance cli mode for compatibility
  -tlslog string
        Filename to write SSL secrets to (allows Wireshark to decrypt TLS connections)
  -trace
        Enable trace level logs
  -transport string
        The transport to use for Conjure connections. Current values include "min" and "obfs4". (default "min")
  -w int
        Number of registrations sent for each connection initiated (default 5)
```

to listen to local connections on default 10500 port.

Then, you'll have a few options:

### Configure HTTP proxy
You will need to ask your particular application(e.g. browser) to use 127.0.0.1:10500 as HTTP proxy.
In Firefox (both mobile and desktop) I prefer to type ```about:config``` into address line and set the following:

 ```
network.proxy.http_port = 10500
network.proxy.http = 127.0.0.1
network.proxy.ssl_port = 10500
network.proxy.ssl = 127.0.0.1
network.proxy.type = 1
```

To disable proxying you may simply set ```network.proxy.type``` back to ```5``` or ```0```.

The same settings are available in Firefox GUI: Preferences->Advanced->Network->Settings

### Configure ssh SOCKS proxy

If you have access to some ssh server, say `socksserver`, you can set up ssh SOCKS tunnel.
First, modify and add the following to `.ssh/config`:

```ssh
Host socksserver-td
Hostname 123.456.789.012
User cookiemonster
ProxyCommand nc -X connect -x 127.0.0.1:10500 %h %p
```

then run `ssh -D1234 socksserver-td -4`

Now in Firefox you could just go to Preferences->Advanced->Network->Settings and set SOCKSv5 host to localhost:1234.

### Command line

To Proxy command line utilities use following environment variables:

 ```bash
export https_proxy=127.0.0.1:10500
export http_proxy=127.0.0.1:10500
wget https://twitter.com
```

Most of the popular utilities also have a flag to specify a proxy.
