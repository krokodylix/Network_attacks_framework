import logging
import ipaddress



# Configure the logging module
logging.basicConfig(level=logging.INFO, format='[+] %(message)s')

MESSAGES = {
    "arguments_error": "provided argument are not valid, check -h or --help for further informations"
}

# Log a success message

def getdevicedata(device):
    logging.info(f"IP: {device['ip']}, MAC: {device['mac']}")


def validateaddress(ip, mask):
    if mask <= 0 or mask >=32:
        raise Exception()
    ipaddress.ip_address(ip)
