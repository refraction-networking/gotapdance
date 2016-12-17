#!/usr/bin/python

import socket
import time
import struct
import sys
from optparse import OptionParser




parser = OptionParser()
parser.add_option("-p", "--port", dest="port", default=8888,
                help="port to listen on or connect to")
parser.add_option("-c", "--connect", dest="connect",
                action="store_true", default=False, help="connect to remote host")
parser.add_option("-H", "--host", dest="host",
                default="127.0.0.1", help="remote host to connect to or bind on")
parser.add_option("-s", "--send", dest="send",
                action="store_true", default=False, help="send data")

(options, args) = parser.parse_args()

connect = options.connect
send = options.send
port = int(options.port)
host = options.host

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

conn = s

if connect:
    s.connect((host, port))
    print 'connected'
else:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    conn, addr = s.accept()
    print 'Connection from', addr



last = time.time()
last_n = 0
last_buf = ''
extra = ''
#s.send('HELLO')

last_time = time.time()

def occasional_print(n):
    global last_time
    if (n % (256*1024)) == 0:
        now = time.time()
        bw = (256*1024*4)/(now - last_time)
        print '%.06f ---> %08x   %.3f MB/s' % (now, n, bw/1000000)
        last_time = now


BUF_SIZE = 1024

if send:
    ##### SEND
    n = 0
    for i in xrange(1024*20*1024/(BUF_SIZE/4)):
        buf = ''
        for j in xrange(BUF_SIZE/4):
            n += 1
            buf += struct.pack('!I', n)

            occasional_print(n)

        conn.sendall(buf)

else:
    ##### RECEIVE
    extra = ''
    last_buf = ''
    last_n = 0
    while True:
        buf = conn.recv(BUF_SIZE)
        buf = extra + buf
        for i in xrange(len(buf)/4):
            n, = struct.unpack('!I', buf[4*i:4*i+4])
            if n != (last_n + 1) and n != 0:
                print '=========ERROR: expected %08x got %08x at offset %d (len %d)' % (last_n+1, n, 4*i, len(buf))
                print ''
                print '----last buf:'
                print last_buf.encode('hex')
                print '----this buf:'
                print buf.encode('hex')
                sys.exit(1)
            last_n = n

            occasional_print(n)
        last_buf = buf
        extra = ''
        if (len(buf)%4) != 0:
            extra = buf[-(len(buf) % 4):]
