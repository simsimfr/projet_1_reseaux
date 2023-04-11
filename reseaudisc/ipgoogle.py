# -*- coding: utf-8 -*-
"""
Created on Tue Apr 11 12:27:10 2023

@author: Home
"""

import pyshark

# Load the Wireshark capture file
capture_file = "C:/Users/Home/Downloads/reseaudisc/traces_reseaux/cameramic150secappelfromend.pcapng"
cap = pyshark.FileCapture(capture_file, display_filter='ip')

# Filter packets with IP addresses starting with 35
for packet in cap:
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst

    if src_ip.startswith('35') or dst_ip.startswith('35'):
        print(f"Packet number: {packet.number}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print("\n")
