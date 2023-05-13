import logging

from src.auxiliary.hostdiscovery import discoverhosts
from src.auxiliary.portscanner import synscan
from src.auxiliary.portscanner import tcpscan
from src.attacks.dhcpstarvation import dhcpstarv
from src.attacks.bruteforce import bruteforce_ssh
from cli import args
from src.config import MESSAGES, logdevicedata, validateaddress, validatemask, porttranslate
from multiprocessing import Process


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
        exit()

    if args.bssh:
        processes = []
        am = args.t
        for i in range(am):
            processes.append(Process(target=bruteforce_ssh, args=(args.sshadr, args.sshp, args.sshuser, args.wordlist, am,i)))
        for proc in processes:
            proc.start()
        for proc in processes:
            proc.join()


    if args.sc:
        ip = projargs["ip"]
        ports = porttranslate(projargs["p"])
        openports = synscan(ip, ports)
        #print("otwarte: " + str(openports))


