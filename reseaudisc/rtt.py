# -*- coding: utf-8 -*-
"""
Created on Mon Apr 10 18:26:14 2023

@author: Home
"""

import pyshark
import matplotlib.pyplot as plt
from datetime import datetime


# Ouvre le fichier PCAP
capture = pyshark.FileCapture('C:/Users/Home/Downloads/reseaudisc/traces_reseaux/cameramic150secappelfromend.pcapng')


# Filtre les paquets pour ne conserver que ceux qui sont de type TCP et qui ont l'indicateur SYN (synchronisation) activé
capture.filter = 'tcp.flags.syn == 1'

# Initialise une liste pour stocker les temps de départ de chaque paquet
start_times = []

# Parcours chaque paquet capturé pour extraire le temps de départ et le stocker dans la liste start_times
for packet in capture:
    if 'TCP' in packet:
        start_times.append(packet.sniff_time.timestamp())

# Réinitialise le curseur de lecture du fichier PCAP au début
capture.reset()

# Initialise une liste pour stocker les temps d'arrivée de chaque paquet
end_times = []

# Parcours chaque paquet capturé pour extraire le temps d'arrivée et le stocker dans la liste end_times
for packet in capture:
    if 'TCP' in packet and packet.tcp.flags.ack == '1':
        end_times.append(packet.sniff_time.timestamp())

# Calcule le Round Trip Time (RTT) de chaque paquet
rtts = [end_times[i] - start_times[i] for i in range(len(start_times))]

# Initialise une figure et un axe pour le graphique
fig, ax = plt.subplots()

# Trace un histogramme des RTTs
ax.hist(rtts, bins=50)

# Configure les étiquettes des axes
ax.set_xlabel('Round Trip Time (ms)')
ax.set_ylabel('Occurrence')

# Affiche le graphique
plt.show()