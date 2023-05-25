from scapy.all import *
import os


def traceroute(targetip):
    return [(snd.ttl, rcv.src) for snd,rcv in sr(IP(dst=targetip, ttl=(1, 50),id=RandShort()) / TCP(flags=0x2), timeout=3 )[0]]
