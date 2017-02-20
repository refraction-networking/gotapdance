# Test Scripts

Collection of quickly written small scripts designed to work with TapDance.

We move fast and break things, so I don't guarantee your computer
won't catch on fire, if you try to use that.

 * twitter_wget.sh - simply wget's twitter

 * go-1.7.4_wget.sh - downloads Golang 1.7.4 acrhive (~81MB)

 * ip.sh - queries http://ipinfo.io with curl for current ip

 * ssh-td.sh - ssh via TapDance. Usage: `./ssh-td.sh $hostname`

 * nc_send.sh - sends random data to poor innocent server
   (specify how much data, e.g. 21k or 42m)

 * seq.py - sends and receives enumerated bytes of data and checks if they are
   received successfully and in order. Blatantly stolen from
   [ewust's repo](https://github.com/ewust/sendseq).
   To use, point TapDance server into seq.py receiver
   and proxy seq.py sender through TapDance client.

