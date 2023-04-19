import logging

from src.auxiliary.hostdiscovery import discoverhosts
from cli import args
from src.config import MESSAGES, getdevicedata

def run(projargs):
    if args.hd:
        try:
            ip = projargs["hn"]
            mask = projargs["hm"]
            hosts = discoverhosts(ip, mask)
            for host in hosts:
                getdevicedata(host)
        except:
            logging.error(MESSAGES["arguments_error"])
