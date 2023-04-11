import pyshark
import matplotlib.pyplot as plt

# Define the function to count protocol occurrences
def count_protocols(packet_count, interface='eth0', display_filter=None):
    capture = pyshark.FileCapture("C:/Users/Home/Downloads/reseaudisc/traces_reseaux/partagedecran150appelfromend.pcapng", display_filter=display_filter)
    protocols = {}

    for packet in capture:
        try:
            protocol = packet.transport_layer
            if hasattr(packet, 'quic'):
                protocol = 'QUIC'
            #elif hasattr(packet, 'tls'):
            #    protocol = 'TLS'
            elif hasattr(packet, 'dns'):
                protocol = 'DNS'
            elif hasattr(packet, 'ssdp'):
                protocol = 'SSDP'
            elif hasattr(packet, 'ssl'):
                protocol = 'SSL'
            elif hasattr(packet, 'mdns'):
                protocol = 'mDNS'

            if protocol not in protocols:
                protocols[protocol] = 1
            else:
                protocols[protocol] += 1
        except AttributeError:
            continue

    return protocols

# Define the function to plot the pie chart
def plot_pie_chart(protocols):
    labels = list(protocols.keys())
    sizes = list(protocols.values())
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    plt.title("Protocols Distribution")
    plt.show()

# Capture packets and count protocols
packet_count = 100
protocols = count_protocols(packet_count)

# Plot the pie chart
plot_pie_chart(protocols)


