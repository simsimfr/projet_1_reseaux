# -*- coding: utf-8 -*-

import pyshark
import matplotlib.pyplot as plt

# Open the capture file in read-only mode
capture = pyshark.FileCapture("C:/Users/Home/Downloads/reseaudisc/traces_reseaux/appelmemewifi.pcapng")

# Create a dictionary to count the number of packets from each source IP address
src_ips = {}
i=0
j=0

for packet in capture:
    
    try:
        src_ip = packet.ip.src
        j+=1
        #print(type(src_ip[0]))
        #print(src_ip[0])
        
        if src_ip in src_ips :
            src_ips[src_ip] += 1
        else:
            src_ips[src_ip] = 1
    except Exception:
        i+=1

# Create a list of the IP addresses and a list of the corresponding packet counts
ips = []
counts = []
for ip, count in src_ips.items():
    ips.append(ip)
    counts.append(count)
print(j)
print(i)

# Plot the pie chart
plt.pie(counts, labels=ips, autopct='%1.1f%%')
plt.title('Destination IP Addresses of Packets')
plt.show()
capture.close()