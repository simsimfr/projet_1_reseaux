# -*- coding: utf-8 -*-
"""
Created on Thu Mar 30 14:26:43 2023

@author: Home
"""

import pyshark
import sys

# Check if input file is provided
if len(sys.argv) < 2:
    print("Usage: python analyze_packets.py <input_file>")
    sys.exit()

# Open input file
input_file = sys.argv[1]
capture = pyshark.FileCapture(input_file)

# Analyze packets
for packet in capture:
    # do something with the packet, e.g. print its source IP address
    print("Source IP address:", packet.ip.src)

# Close capture
capture.close()