from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class Handler(BaseHTTPRequestHandler):
    server_version='Cowrie'
    sys_version=''
    requests=0
    credential_seen=False
    unexpected_host=False
    def log_message(self,*args): pass
    def do_HEAD(self): self.reply()
    def do_GET(self): self.reply()
    def reply(self):
        if self.path=='/metrics':
            body=json.dumps({'requests':Handler.requests,'credential_seen':Handler.credential_seen,'unexpected_host':Handler.unexpected_host}).encode()
        else:
            Handler.requests+=1
            Handler.unexpected_host|=self.headers.get('Host')!='target:8080'
            Handler.credential_seen|=bool(self.headers.get('Authorization') or self.headers.get('Cookie') or self.headers.get('Proxy-Authorization'))
            body=b'<html>isolated diagnostic fixture</html>'
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        if self.command!='HEAD': self.wfile.write(body)
HTTPServer(('0.0.0.0',8080),Handler).serve_forever()
