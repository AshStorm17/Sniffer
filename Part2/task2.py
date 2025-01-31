import pyshark
import os

pcap_filename = "7.pcap"
pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", pcap_filename)

# Open the pcap file
capture = pyshark.FileCapture(pcap_path)
task_file = "task2_packets.txt"

# Task 2: Find the number of TCP packets that satisfy all conditions
count = 0
with open(task_file, "w") as f:
    for packet in capture:
        if hasattr(packet, 'tcp'):
            tcp_layer = packet.tcp

            # Check if SYN flag is set, source port divisible by 11, and sequence number > 100000
            flags = int(tcp_layer.flags, 16)
            src_port = int(tcp_layer.srcport)
            seq_num = int(tcp_layer.seq_raw)

            if (flags & 0x02) and (src_port % 11 == 0) and (seq_num > 100000):
                count += 1
                f.write(f"Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}\n")

print(f"Total TCP packets satisfying all conditions in Task 2: {count}")
