"""
Copyright 2019, Nils Wenzler, All rights reserved.
nils.wenzler@crowgames.de
"""
import logging
import os
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler


class StaticServer(BaseHTTPRequestHandler):

    def do_GET(self):
        root = os.path.join(str(Path(os.path.dirname(os.path.realpath(__file__))).parent), 'static')

        print(root)
        # print(self.path)
        if self.path == '/':
            filename = root + '/index.html'
        else:
            filename = root + self.path

        self.send_response(200)
        if filename[-4:] == '.css':
            self.send_header('Content-type', 'text/css')
        elif filename[-5:] == '.json':
            self.send_header('Content-type', 'application/javascript')
        elif filename[-3:] == '.js':
            self.send_header('Content-type', 'application/javascript')
        elif filename[-4:] == '.ico':
            self.send_header('Content-type', 'image/x-icon')
        else:
            self.send_header('Content-type', 'text/html')
        self.end_headers()
        try:
            with open(filename, 'rb') as fh:
                html = fh.read()
                # html = bytes(html, 'utf8')
                self.wfile.write(html)
        except Exception as e:
            logging.exception(str(e))


def run(server_class=HTTPServer, handler_class=StaticServer, port=7464):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd on port {}'.format(port))
    httpd.serve_forever()