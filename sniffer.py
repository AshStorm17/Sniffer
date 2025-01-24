import pyshark
import matplotlib.pyplot as plt
import time

# Read the .pcap file
capture = pyshark.FileCapture("7.pcap")

num_packets = 0
total_bytes = 0
packet_sizes = []

# Dictionaries for flows as source and destination
source_flows = {}
destination_flows = {}

# Dictionary for data transferred by source-destination pairs
unique_pairs = set()
data_transferred = {}

start_time = time.time()

# Analyze the packets
for packet in capture:
    if hasattr(packet, 'length'):
        num_packets += 1
        # print(num_packets)
        packet_size = int(packet.length)  # Packet length in bytes
        packet_sizes.append(packet_size)
        total_bytes += packet_size
        
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if hasattr(packet, 'transport_layer') and packet.transport_layer:
                src_port = packet[packet.transport_layer].srcport if hasattr(packet[packet.transport_layer], 'srcport') else "N/A"
                dst_port = packet[packet.transport_layer].dstport if hasattr(packet[packet.transport_layer], 'dstport') else "N/A"
            else:
                src_port = "N/A"
                dst_port = "N/A"

            # Add unique source-destination pair
            unique_pairs.add((f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"))

            # Update source and destination flows
            source_flows[src_ip] = source_flows.get(src_ip, 0) + 1
            destination_flows[dst_ip] = destination_flows.get(dst_ip, 0) + 1

            # Update data transferred
            pair_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            data_transferred[pair_key] = data_transferred.get(pair_key, 0) + packet_size

end_time = time.time()
duration = end_time - start_time


# Task 1: Total number of packets and statistics
total_packets = len(packet_sizes)
min_packet_size = min(packet_sizes)
max_packet_size = max(packet_sizes)
avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0

# Task 3: Find the pair with most data transferred
max_data_pair = max(data_transferred, key=data_transferred.get)
max_data_amount = data_transferred[max_data_pair]

# Task 4: Calculate PPS and Mbps
pps = total_packets / duration
mbps = (total_bytes * 8) / (duration * 1_000_000)

# Display Task 1 Results
print(f"Total Data Transferred: {total_bytes} bytes")
print(f"Total Packets Transferred: {total_packets}")
print(f"Minimum Packet Size: {min_packet_size} bytes")
print(f"Maximum Packet Size: {max_packet_size} bytes")
print(f"Average Packet Size: {avg_packet_size:.2f} bytes")

# Plot a histogram of packet sizes
plt.figure(figsize=(10, 6))
plt.hist(packet_sizes, bins=30, color='blue', alpha=0.7, edgecolor='black')
plt.title("Distribution of Packet Sizes")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.grid(axis='y', alpha=0.75)
plt.show()

# Display Task 2 Results
unique_pairs_file = "unique_pairs.txt"

with open(unique_pairs_file, 'w') as upf:
    upf.write("Source IP:Port -> Destination IP:Port\n")
    for pair in unique_pairs:
        upf.write(f"{pair[0]} -> {pair[1]}\n")

print(f"Unique source-destination pairs saved to {unique_pairs_file}.")

# Display Task 3 Results
source_flows_file = "source_flows.txt"
destination_flows_file = "destination_flows.txt"

# Writing source flows
with open(source_flows_file, 'w') as sf:
    sf.write("Source IP Address\tTotal Flows\n")
    for ip, flows in source_flows.items():
        sf.write(f"{ip}\t{flows}\n")

# Writing destination flows
with open(destination_flows_file, 'w') as df:
    df.write("Destination IP Address\tTotal Flows\n")
    for ip, flows in destination_flows.items():
        df.write(f"{ip}\t{flows}\n")

print(f"Results saved to {source_flows_file}, {destination_flows_file}.")
print(f"\nSource-Destination Pair with Most Data Transferred:\n{max_data_pair}: {max_data_amount} bytes")

# Display Task 4 Results
print(f"\nCapture Duration: {duration:.2f} seconds")
print(f"PPS: {pps:.2f} packets/second")
print(f"Throughput: {mbps:.2f} Mbps")