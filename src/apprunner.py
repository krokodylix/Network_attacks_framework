import logging

from src.auxiliary.hostdiscovery import discoverhosts
from src.attacks.dhcpstarvation import dhcpstarv
from cli import args
from src.config import MESSAGES, logdevicedata, validateaddress, validatemask

def run(projargs):
    if args.hd:
        try:
            ip = projargs["hn"]
            mask = projargs["hm"]
            validateaddress(ip)
            validatemask(mask)
            hosts = discoverhosts(ip, mask)
            for host in hosts:
                logdevicedata(host)
        except:
            logging.error(MESSAGES["arguments_error"])

    if args.ds:
        dhcpstarv()

