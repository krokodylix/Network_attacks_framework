from scapy.all import *

def packetsniffer(interface, filter, filename):
    capture = sniff(iface=interface, filter=filter)
    wrpcap(filename, capture)
    capture.summary()
    return capture
