import os
from cli import arg_dict
from src.apprunner import run


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    run(arg_dict)


if __name__ == '__main__':
    main()



