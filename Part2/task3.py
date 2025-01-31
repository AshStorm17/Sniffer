import pyshark
from sympy import isprime
import os

pcap_filename = "7.pcap"
pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", pcap_filename)

# Open the pcap file
capture = pyshark.FileCapture(pcap_path)
task_file = "task3_packets.txt"

# Task 3: Find the number of TCP packets satisfying specific IP and port conditions
count_task3 = 0
with open(task_file, "w") as f:
    for packet in capture:
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            src_ip = packet.ip.src
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
            
            # Check if the source IP matches 18.234.xx.xxx, source port is prime, and destination port is divisible by 11
            if src_ip.startswith("18.234.") and isprime(src_port) and dst_port % 11 == 0:
                count_task3 += 1
                f.write(f"Seq Number: {packet.tcp.seq_raw}, Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}\n")

print(f"Total TCP packets satisfying all conditions in Task 3: {count_task3}")
