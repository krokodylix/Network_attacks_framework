from src.httpserver.server import app
from scapy.all import *
from src.config import packets_to_dict
from src.auxiliary.packetsniffer import packetsniffer
from src.attacks.dos_attacks import httpflood

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    app.run()


if __name__ == '__main__':
    main()



