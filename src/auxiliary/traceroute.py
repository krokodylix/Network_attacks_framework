from scapy.all import *

def traceroute(targetip):
    ans, unans = sr(IP(dst=targetip, ttl=(1,20),id=RandShort()) / TCP(flags=0x2), timeout=20, )
    for snd,rcv in ans:
        print(snd.ttl, rcv.src)
