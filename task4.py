import pyshark

# Open the pcap file
capture = pyshark.FileCapture('7.pcap')
task_file = "task4_packets.txt"

# Task 4: Find the TCP packet where the sum of raw Sequence and Acknowledgement numbers is 2512800625 and checksum ends with 70
with open(task_file, "w") as f:
    for packet in capture:
        if hasattr(packet, 'tcp'):
            tcp_layer = packet.tcp
            seq_num = int(tcp_layer.seq_raw)
            ack_num = int(tcp_layer.ack_raw)
            checksum = tcp_layer.checksum
                    
            if (seq_num + ack_num == 2512800625) and checksum.endswith('70'):
                f.write(f"Seq Number: {seq_num}\nAck Number: {ack_num}\nChecksum: {checksum}\nSource IP: {packet.ip.src}\nDestination IP: {packet.ip.dst}")
                print(packet)
                break