import time
import sys
from scapy.all import sniff

# Get capture duration from command line
capture_duration = int(sys.argv[1])
interface = "eth0"  # Change to your network interface
captured_packets = 0  # Packet counter

# Start time
start_time = time.time()

print(f"Starting packet capture on {interface} for {capture_duration} seconds...")

# Packet handler function
def packet_handler(packet):
    global captured_packets
    captured_packets += 1
    
    # Stop capturing if time exceeds limit
    if time.time() - start_time > capture_duration:
        return False  # Stop sniffing

# Capture packets using Scapy
sniff(iface=interface, prn=packet_handler, store=False, timeout=capture_duration)

# Display results
print("\nCapture Summary:")
print(f"Total Captured Packets: {captured_packets}")
