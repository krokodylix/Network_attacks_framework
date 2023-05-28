from scapy.all import *
import os


def traceroute(targetip):
    t2r=[]
    for snd,rcv in sr(IP(dst=targetip, ttl=(1, 10),id=RandShort()) / TCP(flags=0x2), timeout=3 )[0]:
        t2r.append({
            "id": snd.ttl,
            "ip": rcv.src
        })
    return t2r