from scapy.all import *
import logging

def traceroute(targetip):
    [print(snd.ttl, rcv.src) for snd,rcv in sr(IP(dst=targetip, ttl=(1,20),id=RandShort()) / TCP(flags=0x2), timeout=4 )[0]]
