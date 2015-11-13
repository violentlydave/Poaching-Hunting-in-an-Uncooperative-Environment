#!/usr/bin/python
#
# simple_http_wpad.py - d.e.switzer # ZGF2aWQgZG90IGUgZG90IHN3aXR6ZXIgYXQgdGVoZ21haWx6Cg==
#
# a simple HTTP server to serve up WPAD files (or misc other stuff) 
#
import sys,SimpleHTTPServer,SocketServer
import BaseHTTPServer

__author__ = 'd.switzer'


if len(sys.argv) > 1:
	PORT = int(sys.argv[1])
else:
	PORT = 80

my_handler = SimpleHTTPServer.SimpleHTTPRequestHandler
my_handler.extensions_map.update({
 '.dat': 'application/x-ns-proxy-autoconfig','.pac': 'application/x-ns-proxy-autoconfig' });
httpd = SocketServer.TCPServer(("", PORT), my_handler)

try:
	print "-------------------------------------------------"
	print "Super Simple HTTP Server - d.switzer 2015"
	print "-------------------------------------------------"
	print "Listening on port ", PORT
	httpd.serve_forever()

except KeyboardInterrupt:
	print "Otay, closing up socket-shop..."
	httpd.socket.close()
