import pyshark

# Replace 'path/to/your/capture_file.pcap' with the path to your capture file
capture_file = 'C:/Users/Home/Downloads/reseaudisc/traces_reseaux/cameramic150secappelfromend.pcapng'

# Create a capture object
cap = pyshark.FileCapture(capture_file, display_filter='http')


# Iterate through packets in the capture
for pkt in cap:
    try:
        # Check if the packet has an 'expert' layer
        if hasattr(pkt, 'expert'):
            # Iterate through expert messages
            for message in pkt.expert.message:
                if "malformed" in message.lower():
                    print(f'Malformed packet found: {pkt.number}')
                    break
    except AttributeError:
        # Handle the case when the packet doesn't have the 'expert' layer
        pass
