import logging
import ipaddress
import warnings



# Configure the logging module

logging.basicConfig(level=logging.INFO, format='[+] %(message)s')
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
warnings.simplefilter("ignore")


MESSAGES = {
    "arguments_error": "provided argument are not valid, check -h or --help for further informations",
    "password_found": "password, found: "
}

# Log a success message

def logdevicedata(device):
    logging.info(f"IP: {device['ip']}, MAC: {device['mac']}")


def validateaddress(ip):
    ipaddress.ip_address(ip)

def validatemask(mask):
    if mask <= 0 or mask >=32:
        raise Exception()

