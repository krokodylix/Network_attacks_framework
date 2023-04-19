import argparse


parser = argparse.ArgumentParser(description="bot23L, CLI")

# Host discovery parameters
parser.add_argument('-hd', action='store_true', help='perform hostdiscovry') # main host discovery flag
parser.add_argument('-hn', type=str, help='network\'s address for host discovery')
parser.add_argument('-hm', type=int, help='subnetwork mask')

# DHCP starvation attack
parser.add_argument('-ds', action='store_true', help='perform dhcp starvation attack')

# BRUTE FORCE SECTION

# ssh brute force

parser.add_argument('-bssh', action='store_true', help='perform ssh brute force')
parser.add_argument('-sshadr', type=str, help='victim address')
parser.add_argument('-sshuser', type=str, help='victim username')
parser.add_argument('-sshp', type=int, help='ssh port')
parser.add_argument('-wordlist', type=str, help='passwords wordlist')


parser.add_argument('-t', type=int, help='threads')

args = parser.parse_args()

arg_dict = {}
for arg in vars(args):
    arg_dict[arg] = getattr(args, arg)
