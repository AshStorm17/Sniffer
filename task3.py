import pyshark
from sympy import isprime

# Open the pcap file
capture = pyshark.FileCapture('7.pcap')

# Task 3: Find the number of TCP packets satisfying specific IP and port conditions
count_task3 = 0
for packet in capture:
    if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
        src_ip = packet.ip.src
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        
        # Check if the source IP matches 18.234.xx.xxx, source port is prime, and destination port is divisible by 11
        if src_ip.startswith("18.234.") and isprime(src_port) and dst_port % 11 == 0:
            count_task3 += 1
            print(f"Task 3 - Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")

print(f"Total TCP packets satisfying all conditions in Task 3: {count_task3}")