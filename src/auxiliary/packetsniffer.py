from scapy.all import *

def handler(packet, collected_data):
    collected_data.append(packet)

def packetsniffer(interface, duration):
    collected_data = []
    end_time = time.time() + duration

    while time.time() < end_time:
        sniff(iface=interface, prn=lambda pkt: handler(pkt, collected_data), count=1)

    return collected_data
