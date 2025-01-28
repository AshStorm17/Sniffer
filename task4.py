import pyshark

# Open the pcap file
capture = pyshark.FileCapture('7.pcap')

# Task 4: Find the TCP packet where the sum of raw Sequence and Acknowledgement numbers is 2512800625 and checksum ends with 70
for packet in capture:
    if hasattr(packet, 'tcp'):
        tcp_layer = packet.tcp
        seq_num = int(tcp_layer.seq_raw)
        ack_num = int(tcp_layer.ack_raw)
        checksum = tcp_layer.checksum
                
        if (seq_num + ack_num == 2512800625) and checksum.endswith('70'):
            print(f"Task 4 - Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}, Checksum: {checksum}")