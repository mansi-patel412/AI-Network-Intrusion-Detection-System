from scapy.all import sniff

# This module is now simpler as the main logic is in the Streamlit app.
# The core function is still 'sniff', but it will be called with a timeout.

def get_packet_details(packet):
    """
    A helper function to extract basic details from a packet.
    (Can be expanded later if needed)
    """
    details = {}
    if 'IP' in packet:
        details['src_ip'] = packet['IP'].src
        details['dst_ip'] = packet['IP'].dst
    if 'TCP' in packet:
        details['src_port'] = packet['TCP'].sport
        details['dst_port'] = packet['TCP'].dport
    if 'UDP' in packet:
        details['src_port'] = packet['UDP'].sport
        details['dst_port'] = packet['UDP'].dport
    return details

