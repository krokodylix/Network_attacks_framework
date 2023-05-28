import ipaddress
import warnings
import sys
from scapy.all import *




MESSAGES = {
    "arguments_error": "provided argument are not valid, check -h or --help for further informations",
    "password_found": "password, found: "
}

# Log a success message




def validateaddress(ip):
    ipaddress.ip_address(ip)

def validatemask(mask):
    if mask <= 0 or mask >=32:
        raise Exception()


def validateport(port):
    if port > 0 and port <65535:
        return port
    else:
        raise Exception()


def porttranslate(ports):
    result = []
    if not ports:
        result = [i for i in range(1,10000)]
    else:
        try:
            separated = ports.split(",")
            for num in separated:
                if "-" in num:
                    y = num.split("-")
                    a = validateport(int(min(y)))
                    b = validateport(int(max(y)))
                    for i in range(a, b):
                        result.append(i)
                else:
                    result.append(validateport(int(num)))
        except Exception as e:
            print(f"Error: {e}")

    return result


def packets_to_dict(collected_data):
    packet_list = []

    for packet in collected_data:
        packet_dict = {}

        try:
            packet_dict["sip"] = packet[IP].src
            packet_dict["dip"] = packet[IP].dst

            if packet.haslayer(TCP):
                packet_dict["protocol"] = "TCP"
                packet_dict["sport"] = packet[TCP].sport
                packet_dict["dport"] = packet[TCP].dport


            elif packet.haslayer(UDP):
                packet_dict["protocol"] = "UDP"
                packet_dict["sport"] = packet[UDP].sport
                packet_dict["dport"] = packet[UDP].dport

            if packet.haslayer(Raw):
                packet_dict["payload"] = str(packet[Raw])
            else:
                packet_dict["payload"] = ""
            #if packet.haslayer(ICMP):
            #    packet_dict["Protocol"] = "ICMP"
            #    packet_dict["ICMP Type"] = packet[ICMP].type
            #    packet_dict["ICMP Code"] = packet[ICMP].code


            packet_list.append(packet_dict)
        except:
            continue
    return packet_list



services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP - Server",
    68: "DHCP - Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    118: "SQL - Services",
    119: "NNTP",
    123: "NTP",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD/LPR",
    520: "RIP",
    554: "RTSP",
    587: "SMTP (Submission)",
    631: "IPP",
    636: "LDAPS",
    873: "rsync",
    990: "FTPS - Control",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5500: "VNC",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP (Alternative)",
    8080: "HTTP Proxy",
    8443: "HTTPS (Alternative)",
    8888: "HTTP (Alternative)",
    9090: "HTTP (Alternative)",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
    50000: "DB2",
    54321: "VMware ESXi"
}



#interface = sys.argv[1]
#victimIP = sys.argv[2]
#gatewayIP = sys.argv[3]