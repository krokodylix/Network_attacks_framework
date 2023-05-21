from scapy.all import *
import socket
import logging


from scapy.layers.inet import TCP
from scapy.all import IP, TCP, sr1


def tcpscan(targetip,ports):
    openports = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        for port in ports:
            result = sock.connect_ex((targetip, port))
            if result == 0:
                logging.info(f"Port {port} is open on {targetip}")
                openports.append(port)
            else:
                logging.info(f"Port {port} is closed on {targetip}")
        sock.close()
    except Exception as e:
        logging.info(f"Error: {e}")

    return openports



def synscan(target_ip, ports):
    for port in ports:
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(sport=1234, dport=port, flags="S")
        packet = ip_packet / tcp_packet
        response = sr1(packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":
                logging.info(f"Port {port} is open")
            elif response[TCP].flags == "RA":
                logging.info(f"Port {port} is closed")
        else:
            logging.exception(f"Port {port} is filtered or no response received")


def nullscan(target_ip, ports):
    for port in ports:
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="")
        packet = ip_packet / tcp_packet
        response = sr1(packet, verbose=False, timeout=5)

        if response is None:
            logging.info(f"Port {port} on {target_ip} is open or filtered.")
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x14:
                logging.info(f"Port {port} on {target_ip} is closed.")
            elif response.getlayer(TCP).flags == 0x04:
                logging.info(f"Port {port} on {target_ip} is open.")
        else:
            logging.info(f"Port {port} on {target_ip} could not be reached.")


def finscan(target_ip, ports):
    for port in ports:
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(dport=port, flags="F")
        packet = ip_packet / tcp_packet
        response = sr1(packet, verbose=False, timeout=5)

        if response is None:
            logging.info(f"Port {port} on {target_ip} is open or filtered.")
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x14:
                logging.info(f"Port {port} on {target_ip} is closed.")
            elif response.getlayer(TCP).flags == 0x04:
                logging.info(f"Port {port} on {target_ip} is open.")
        else:
            logging.info(f"Port {port} on {target_ip} could not be reached.")





















