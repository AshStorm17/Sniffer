import time
import sys
import matplotlib.pyplot as plt
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from sympy import isprime

# Get capture duration from command line
capture_duration = int(sys.argv[1])
interface = "eth0"

# Initialize counters and data structures
captured_packets = 0
total_bytes = 0
packet_sizes = []
src_dst_pairs = set()
src_flows = defaultdict(int)
dst_flows = defaultdict(int)
data_transfer = defaultdict(int)  # (src_ip:src_port, dst_ip:dst_port) → total bytes

# Initialize packet matching results
task1 = []
task2 = []
task3 = []
task4 = []

# Start time
start_time = time.time()

print(f"Starting packet capture on {interface} for {capture_duration} seconds...")

# Packet handler function
def packet_handler(packet):
    global captured_packets, total_bytes
    captured_packets += 1
    packet_len = len(packet)
    total_bytes += packet_len
    packet_sizes.append(packet_len)

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)

        if src_port and dst_port:
            src_dst_pairs.add((f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"))
            src_flows[src_ip] += 1
            dst_flows[dst_ip] += 1
            data_transfer[(f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")] += packet_len

        # Task 1: ACK & PSH flag set, sum of src & dst ports = 60303
        if TCP in packet and packet[TCP].flags & 0x18 == 0x18:
            if src_port + dst_port == 60303:
                task1.append((src_ip, dst_ip))

        # Task 2: SYN flag set, src port divisible by 11, sequence number > 100000
        if TCP in packet and packet[TCP].flags & 0x02:
            if src_port % 11 == 0 and packet[TCP].seq > 100000:
                task2.append((src_ip, dst_ip))

        # Task 3: Source IP of form 18.234.xx.xxx, source port prime, destination port divisible by 11
        if src_ip.startswith("18.234") and isprime(src_port) and dst_port % 11 == 0:
            task3.append((packet[TCP].seq, src_ip, dst_ip))

        # Task 4: Sum of sequence & acknowledgment number = 2512800625, last two checksum digits = 0x70
        if TCP in packet and packet[TCP].seq + packet[TCP].ack == 2512800625:
            if hex(packet[TCP].chksum)[-2:] == "70":
                task4.append((packet[TCP].chksum, packet[TCP].ack, packet[TCP].seq, packet))

    # Stop capturing if time exceeds limit
    if time.time() - start_time > capture_duration:
        return False  # Stop sniffing

# Capture packets using Scapy
sniff(iface=interface, prn=packet_handler, store=False, timeout=capture_duration)

# Compute packet size statistics
min_packet_size = min(packet_sizes) if packet_sizes else 0
max_packet_size = max(packet_sizes) if packet_sizes else 0
avg_packet_size = (total_bytes / captured_packets) if captured_packets > 0 else 0

# Identify the source-destination pair with the most data transferred
most_data_pair = max(data_transfer, key=data_transfer.get) if data_transfer else None

# Save results to file
with open("part1.txt", "w") as f:
    f.write("Capture Summary:")
    f.write(f"\nTotal Packets Captured: {captured_packets}")
    f.write(f"\nTotal Data Transferred: {total_bytes} bytes")
    f.write(f"\nMin Packet Size: {min_packet_size} bytes")
    f.write(f"\nMax Packet Size: {max_packet_size} bytes")
    f.write(f"\nAverage Packet Size: {avg_packet_size:.2f} bytes")

    f.write("\n\nUnique Source-Destination Pairs:")
    for pair in src_dst_pairs:
        f.write(f"\n{pair[0]} → {pair[1]}")

    f.write("\n\nFlows per Source IP:\n")
    for ip, flows in src_flows.items():
        f.write(f"{ip}\t{flows}\n")

    f.write("\nFlows per Destination IP:\n")
    for ip, flows in dst_flows.items():
        f.write(f"{ip}\t{flows}\n")

    if most_data_pair:
        f.write(f"\n\nSource-Destination Pair with Most Data Transferred: {most_data_pair} → {data_transfer[most_data_pair]} bytes")

with open("part2.txt", "w") as f:
    # Write packet-matching results
    f.write("Packets Matching Task 1 (ACK & PSH, port sum = 60303):\n")
    for src, dst in task1:
        f.write(f"{src} → {dst}\n")

    f.write("\nPackets Matching Task 2 (SYN, src port % 11, seq > 100000):\n")
    for src, dst in task2:
        f.write(f"{src} → {dst}\n")

    f.write("\nPackets Matching Task 3 (src 18.234.xx.xxx, src prime, dst % 11):\n")
    for seq, src, dst in task3:
        f.write(f"{seq} : {src} → {dst}\n")

    f.write("\nPackets Matching Task 4 (seq + ack = 2512800625, checksum ending in 70):\n")
    for chksum, ack, seq, packet in task4:
        f.write(f"Packet: {packet.summary()}\nChecksum: {chksum}\nAck: {ack}\nSeq: {seq}\n\n")

# Plot histogram of packet sizes
plt.figure(figsize=(10, 5))
plt.hist(packet_sizes, bins=20, edgecolor='black', alpha=0.7)
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.title("Distribution of Packet Sizes")
plt.grid(True)
plt.show()
