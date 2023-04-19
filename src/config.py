import logging

# Configure the logging module
logging.basicConfig(level=logging.INFO, format='[+] %(message)s')

MESSAGES = {
    "arguments_error": "provided argument are not valid, check -h or --help for further informations"
}

# Log a success message

def getdevicedata(device):
    logging.info(f"IP: {device['ip']}, MAC: {device['mac']}")
