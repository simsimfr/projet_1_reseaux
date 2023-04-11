import socket
import pyshark
import matplotlib.pyplot as plt

prefix = "IPPROTO_"
protocol_table = {num: name[len(prefix):] for name, num in vars(socket).items() if name.startswith(prefix)}

capture = pyshark.FileCapture("C:/Users/Home/Downloads/reseaudisc/traces_reseaux/nocamnomic150secappelfromend.pcapng")

protocol_counts = {}

for packet in capture:
    protocol = None
    src_port = None
    dst_port = None

    if 'IPV6 Layer' in str(packet.layers):
        protocol = [protocol_type for [protocol_number, protocol_type] in protocol_table.items()
                    if protocol_number == int(packet.ipv6.nxt)]

        if hasattr(packet, 'udp'):
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
        elif hasattr(packet, 'tcp'):
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)

    elif 'IP Layer' in str(packet.layers):
        protocol = [protocol_type for [protocol_number, protocol_type] in protocol_table.items()
                    if protocol_number == int(packet.ip.proto)]

        if hasattr(packet, 'udp'):
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
        elif hasattr(packet, 'tcp'):
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)

    # Check for RTCP
    if src_port and dst_port and ((src_port % 2 == 0 and dst_port == src_port + 1) or (dst_port % 2 == 0 and src_port == dst_port + 1)):
        protocol = ['RTCP']

    if protocol:
        protocol_name = protocol[0]
        if protocol_name in protocol_counts:
            protocol_counts[protocol_name] += 1
        else:
            protocol_counts[protocol_name] = 1

# Create pie chart
labels = list(protocol_counts.keys())
sizes = list(protocol_counts.values())

fig, ax = plt.subplots()
ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
ax.axis('equal')  # Equal aspect ratio ensures the pie chart is circular.

plt.title("Protocol Distribution")
plt.show()
