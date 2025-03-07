import pyshark
import os

pcap_filename = "7.pcap"
pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", pcap_filename)

# Open the pcap file
capture = pyshark.FileCapture(pcap_path)
task_file = "task1_packets.txt"

# Task 1: Find the IP addresses of source and destination for a TCP packet with ACK and PSH flags set and sum of source and destination ports = 60303
count = 0
with open(task_file, "w") as f:
    for packet in capture:
        if hasattr(packet, 'tcp'):
            tcp_layer = packet.tcp
            flags = int(tcp_layer.flags, 16)
            src_port = int(tcp_layer.srcport)
            dst_port = int(tcp_layer.dstport)
            x = src_port + dst_port
            if(x == 60303):
                count += 1
                    
            if (flags & 0x10) and (flags & 0x08) and (src_port + dst_port == 60303):
                f.write(f"Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")

f"Total TCP packets satisfying all conditions in Task 1: {count}"
                