from scapy.all import ARP, Ether, srp
from src.config import validateaddress, validatemask

def discoverhosts(ip, mask):
    validateaddress(ip)
    validatemask(mask)
    arp = ARP(pdst=f'{ip}/{mask}')
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices