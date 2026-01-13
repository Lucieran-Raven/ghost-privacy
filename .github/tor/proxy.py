#!/usr/bin/env python3
# Simple HTTP proxy to Netlify
import http.server
import socketserver
import requests
from urllib.parse import urljoin
import sys

NETLIFY_URL = "https://ghostprivacy.netlify.app"
PORT = 8080

class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            # Forward request to Netlify with proper Host header
            url = urljoin(NETLIFY_URL, self.path)
            headers = dict(self.headers)
            headers['Host'] = 'ghostprivacy.netlify.app'
            
            response = requests.get(url, headers=headers, timeout=10)
            
            # Send response back to client
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                if header.lower() not in ['content-encoding', 'transfer-encoding']:
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
            
        except Exception as e:
            self.send_error(500, f"Proxy error: {str(e)}")
    
    def do_POST(self):
        try:
            # Get POST data
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # Forward request to Netlify
            url = urljoin(NETLIFY_URL, self.path)
            headers = dict(self.headers)
            headers['Host'] = 'ghostprivacy.netlify.app'
            
            response = requests.post(url, data=post_data, headers=headers, timeout=10)
            
            # Send response back to client
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                if header.lower() not in ['content-encoding', 'transfer-encoding']:
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
            
        except Exception as e:
            self.send_error(500, f"Proxy error: {str(e)}")

    def do_OPTIONS(self):
        # Handle CORS preflight requests
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), ProxyHandler) as httpd:
        print(f"Proxy server running on port {PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down proxy server...")
            httpd.shutdown()
