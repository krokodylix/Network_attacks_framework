import os
from cli import arg_dict
from src.apprunner import run


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    run(arg_dict)


if __name__ == '__main__':
    main()
    #from src.auxiliary.portscanner import synscan
    #synscan('192.168.189.135',[22,123,80])
