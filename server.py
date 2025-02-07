from http.server import SimpleHTTPRequestHandler, HTTPServer

class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Hello World</h1></body></html>")

server_address = ('localhost', 1110)

httpd = HTTPServer(server_address, MyHandler)

print("Starting server on http://localhost:1110")
httpd.serve_forever()
