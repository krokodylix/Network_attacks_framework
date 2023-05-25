import logging
import ipaddress
import warnings
import sys


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


def validateport(port):
    if port > 0 or port <65535:
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


interface = sys.argv[1]
victimIP = sys.argv[2]
gatewayIP = sys.argv[3]