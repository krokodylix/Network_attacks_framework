from scapy.all import *
import socket



from scapy.layers.inet import TCP
from scapy.all import IP, TCP, sr1


def tcpscan(target_ip, ports):
    openports = []
    for port in ports:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response is not None and response.haslayer(TCP) and response[TCP].flags == "SA":
             openports.append(port)
    return openports



def synscan(target_ip, ports):
    openports = []
    for port in ports:
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(sport=1234, dport=port, flags="S")
        packet = ip_packet / tcp_packet
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":
                openports.append(port)

    return openports

def nullscan(target_ip, ports):
    openports = []
    for port in ports:
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="")
        packet = ip_packet / tcp_packet
        response = sr1(packet, verbose=False, timeout=5)
        if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
            openports.append(port)
    return openports


def finscan(target_ip, ports):
    openports = []
    for port in ports:
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="F")
        packet = ip_packet / tcp_packet
        response = sr1(packet, verbose=False, timeout=5)
        if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
            openports.append(port)
    return openports





















