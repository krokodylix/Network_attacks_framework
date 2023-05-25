from scapy.all import *
import os


def traceroute(targetip):
    os.system(f'tracert {targetip}')
    #[print(snd.ttl, rcv.src) for snd,rcv in sr(IP(dst=targetip, ttl=(1, 50),id=RandShort()) / TCP(flags=0x2), timeout=3 )[0]]
