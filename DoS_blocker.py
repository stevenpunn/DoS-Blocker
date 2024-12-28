import os
import sys
import time                             # helps to determine transfer rates between packets
from collections import defaultdict     # store and manage packets for each IP addresss
from scapy.all import sniff, IP         # allows analization of network packets

MAXPACKETS = 40                          # maximum packet rate per IP address
print(f"THRESHOLD: {MAXPACKETS}")

def packet_callback(packet):
    src_ip = packet[IP].src             # extract packet from IP address
    packet_count[src_ip] += 1           
    current_time = time.time()          # record the current time
    time_interval = current_time - start_time[0]

    # determine if a DoS attack is currently happening, 1x per second
    if time_interval >= 1:
        for ip, count in packet_count.items():              # iterate through packet counts per IP address
            packet_rate = count / time_interval
            if packet_rate > MAXPACKETS and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")         # block ip using os and add to a list of blocked IPs
                blocked_ips.add(ip)
        
        # after 1 iteration, clear packet count and restart time
        packet_count.clear()                       
        start_time[0] = current_time

# declare main guard
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Script requires root privileges.")
        sys.exit(1)

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring Network Traffic...")
    sniff(filter="ip", prn=packet_callback)

# sudo iptables -L INPUT -n
# sudo py dos_blocker.py
# sudo iptables -D INPUT -s {IPADDRESS} -j DROP to unblock from packet sender
