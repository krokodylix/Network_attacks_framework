import os
from src.attacks.dhcpstarvation import dhcpstarv


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    dhcpstarv()


if __name__ == '__main__':
    main()