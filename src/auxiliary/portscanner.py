from scapy.all import *
import socket

from scapy.layers.inet import TCP


def tcpscan(targetip,ports):
    openports = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        for port in ports:
            result = sock.connect_ex((targetip, port))
            if result == 0:
                print(f"Port {port} is open on {targetip}")
                openports.append(port)
            else:
                print(f"Port {port} is closed on {targetip}")
        sock.close()
    except Exception as e:
        print(f"Error: {e}")

    return openports

def synscan(targetip,ports):
    openports = []
    try:
        p = IP(dst=targetip) / TCP(dport=ports, flags='S')  # Forging SYN packet
        answers, un_answered = sr(p,inter=0.5,retry=2, timeout=1)  # Send the packets
        for req, resp in answers:
            if not resp.haslayer(TCP):
                continue
            tcp_layer = resp.getlayer(TCP)
            if tcp_layer.flags == 0x12:
                print(f"Port {port} is open on {targetip}")
                openports.append(port)
            elif tcp_layer.flags == 0x14:
                print(f"Port {port} is closed on {targetip}")
        print(answers)
    except Exception as e:
        print(f"Error: {e}")

    return openports

def nullscan():
    print("1")


def finscan():
    print("2")

def xmasscan(targetip,ports):
    ans, unans = sr(IP(dst=targetip) / TCP(dport=ports, flags="FPU"))
   
    if ans and ans.haslayer(TCP) and ans[TCP].flags.R:
        print("The RST flag is set in the response packet.")
    else:
        print("The RST flag is not set in the response packet.")



#def scanports(targetip):
#    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targetip)
#
#    ans, unans = srp(request, timeout=2, retry=1)
#    result = []
#
#    for sent, received in ans:
#        result.append({'IP': received.psrc, 'MAC': received.hwsrc})
#
#    return result
#   ans, unans = sr(IP(dst=targetip) / TCP(dport=[0,80,445, 1024], flags="A"), timeout=2)
#   print('dupa')
#   for s, r in ans:
#       if s[TCP].dport == r[TCP].sport:
#           print("%d is unfiltered" % s[TCP].dport)
#   for s in unans:
#       print("%d is filtered" % s[TCP].dport)

#   #ans1, unans1 = sr(IP(dst=targetip) / TCP(dport=80, flags="FPU"))

















#   sourceport = RandShort()


#   openports=[]
#   ports=[20,21,22,23,15,80,443,445,25,123,1434,161,162,110,3389]


#   print("syn scan on, %s with ports %s" % (targetip, ports))
#   for port in ports:
#       pkt = sr1(IP(dst=targetip) / TCP(sport=sourceport, dport=port, flags="S"), timeout=1, verbose=0)
#       print('dupa')
#       if pkt is not None:
#           if pkt.haslayer(TCP):
#               if pkt[TCP].flags == 20:
#                   #print_ports(port, "Closed")
#                   print(str(port) + ' closed')
#               elif pkt[TCP].flags == 18:
#                   openports.append(port)
#                   print(str(port) + ' open')
#               else:
#                   #print_ports(port, "TCP packet resp / filtered")
#                   print(str(port) + ' filtered')
#           elif pkt.haslayer(ICMP):
#               #print_ports(port, "ICMP resp / filtered")
#               print(str(port) + ' filtered')
#           else:
#               #print_ports(port, "Unknown resp")
#               print(pkt.summary())
#       else:
#          # print_ports(port, "Unanswered")
#          print(str(port) + ' unanswered')

#   print(openports)

#   return openports


