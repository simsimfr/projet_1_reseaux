# -*- coding: utf-8 -*-
"""
Created on Sun Apr  2 17:11:58 2023

@author: Home
"""


import pyshark
import matplotlib.pyplot as plt

# Ouvrir la capture Wireshark
capture = pyshark.FileCapture("C:/Users/Home/Downloads/reseaudisc/traces_reseaux/partagedecran150appelfromend.pcapng")

# Initialiser un dictionnaire pour stocker le nombre de paquets pour chaque protocole
protocols = {}

# Parcourir chaque paquet dans la capture
for packet in capture:
    # Vérifier si le paquet a un champ "Protocol" et l'ajouter au dictionnaire
    try:
        protocol = packet.highest_layer  # Get the highest level protocol
        protocols[protocol] = protocols.get(protocol, 0) + 1
    except:
        print("An error occurred.")

# Générer le graphique circulaire
plt.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
plt.title("Répartition des protocoles dans la capture,partage d'écran" )
plt.axis('equal')
plt.show()
