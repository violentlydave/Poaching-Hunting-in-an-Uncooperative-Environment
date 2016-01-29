#!/usr/bin/python
#
# simple_http_wpad.py - d.e.switzer # ZGF2aWQgZG90IGUgZG90IHN3aXR6ZXIgYXQgdGVoZ21haWx6Cg==
#
# a simple HTTP server to serve up WPAD files (or misc other stuff) 
#
import argparse,sys,SimpleHTTPServer,SocketServer
import BaseHTTPServer

__author__ = 'd.e.switzer'

def get_me_some_args():
    parser = argparse.ArgumentParser(
        description='Simple HTTP server that serves data from local dir.')
    parser.add_argument(
        '-p', '--port', type=int, help='Port for the HTTP server to run on.', required=False, default='80')
    args = parser.parse_args()
    port = args.port
    return port

port = get_me_some_args()
my_handler = SimpleHTTPServer.SimpleHTTPRequestHandler
my_handler.extensions_map.update({
 '.dat': 'application/x-ns-proxy-autoconfig','.pac': 'application/x-ns-proxy-autoconfig' });
httpd = SocketServer.TCPServer(("", port), my_handler)

try:
	print "-------------------------------------------------"
	print "Super Simple HTTP Server - d.switzer 2015"
	print "-------------------------------------------------"
	print "Listening on port ", port
	httpd.serve_forever()

except KeyboardInterrupt:
	print "Otay, closing up socket-shop..."
	httpd.socket.close()
