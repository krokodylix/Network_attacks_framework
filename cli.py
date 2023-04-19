import argparse


parser = argparse.ArgumentParser(description="bot23L, CLI")
# Host discovery parameters
parser.add_argument('-hd', action='store_true', help='perform hostdiscovry') # main host discovery flag
parser.add_argument('-hn', type=str, help='network\'s address for host discovery')
parser.add_argument('-hm', type=int, help='subnetwork mask')


args = parser.parse_args()

arg_dict = {}
for arg in vars(args):
    arg_dict[arg] = getattr(args, arg)
