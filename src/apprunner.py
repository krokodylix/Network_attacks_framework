import platform
import os
import subprocess
import sys
import ctypes


def rungui():
    runos = platform.system()
    if runos == "Linux":
        if os.getuid() != 0:
            print('run this code with root privilages')
            sys.exit()
        os.system("bash ./os_scripts/linux_guirunner.sh")
    elif runos == "Windows":
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print('run this code with administrator privilages')
            sys.exit()
        #backend_process = subprocess.run(['powershell.exe', 'os_scripts\\windows_backend.ps1'])
        #frontend_process = subprocess.run(['powershell.exe', 'os_scripts\\windows_guirunner.ps1'])
#
        #backend_process.wait()
        #frontend_process.wait()

