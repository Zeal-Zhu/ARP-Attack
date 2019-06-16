# -*- coding: UTF-8 -*-
import dpkt  # 是用来解析数据包的
import pcap  # 用于抓包
import re
import requests
from PIL import Image
from io import BytesIO
from optparse import OptionParser
import sys
import logging
# import celery # 异步工具

imgurllist = []
urllist = []
logname = "log/record.log"


def main():
    usage = "Usage: [-i interface]"
    parser = OptionParser(usage)
    parser.add_option('-i', dest='interface',
                      help='specify interface(input eth0, en0 wlan0 or more)')
    (options, args) = parser.parse_args()
    if options.interface:
        interface = options.interface
        pc = pcap.pcap(interface)
        pc.setfilter('tcp port 80')
        # pc.setfilter('dst host 192.168.199.244 or src host 192.168.199.244')
        # pc.setfilter('src host 192.168.199.244')
        for ptime, pdata in pc:
            get_request_url(pdata)
            # get_response(pdata)
    else:
        parser.print_help()
        sys.exit(0)


def get_response(pdata):
    p = dpkt.ethernet.Ethernet(pdata)
    ipdata = p.data
    tcpdata = p.data.data
    logging.info('='*30)
    sip = '%d.%d.%d.%d' % tuple(map(ord, list(ipdata.src)))
    dip = '%d.%d.%d.%d' % tuple(map(ord, list(ipdata.dst)))
    # logging.info("ip track: " + sip + " --> " + dip)
    if dip == '192.168.199.244':
        try:
            httpresponse = dpkt.http.Response(tcpdata.data)
            # print httpresponse
            if 'content-type' in httpresponse.headers and 'text/html' in httpresponse.headers['content-type']:
                logging.info("http response: " +
                             repr(httpresponse).encode('utf-8'))
                logging.info("http header: " +
                             repr(httpresponse.headers).encode('utf-8'))
                logging.info("http body: "+httpresponse.body)
        except(dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
            logging.warning(e)
            pass


def get_request_url(pdata):
    global urllist
    p = dpkt.ethernet.Ethernet(pdata)
    ipdata = p.data
    tcpdata = p.data.data
    if len(tcpdata.data) > 0 and ipdata.__class__.__name__ == 'IP' and tcpdata.__class__.__name__ == 'TCP' and tcpdata.dport == 80:
        # pa = re.compile(r'GET (.*?)') pa=re.compile(r'GET (.*?\.jpg)')  # |.*?\.png|.*?\.gif
        # url = re.findall(pa, tcpdata.data)
        # logging.info("in loop...")
        try:
            httprequest = dpkt.http.Request(tcpdata.data)
            if isinstance(tcpdata, dpkt.tcp.TCP) and httprequest.method == 'GET':  # tcp data packet
                sip = '%d.%d.%d.%d' % tuple(map(ord, list(ipdata.src)))
                dip = '%d.%d.%d.%d' % tuple(map(ord, list(ipdata.dst)))
                logging.info("ip track: " + sip + " --> " + dip)
                if 'referer' in httprequest.headers:
                    fullurl = httprequest.headers['referer']
                elif 'host' in httprequest.headers:
                    fullurl = 'http://' + \
                        httprequest.headers['host'] + httprequest.uri

                if fullurl not in urllist:
                    urllist.append(fullurl)
                    logging.info("http get full url of %d : %s" % (len(urllist), fullurl))
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
            # logging.warning(e)
            pass



def debug():
    pc=pcap.pcap('en0')
    # pc.setfilter('tcp port 80')
    # pc.setfilter('dst host 192.168.199.244 or src host 192.168.199.244')
    pc.setfilter('src host 192.168.199.244')
    for ptime, pdata in pc:
        # getimg(pdata)
        getinfo(pdata)


if __name__ == '__main__':
    logging.basicConfig(filename=logname,
                        filemode='a',
                        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                        datefmt='%H:%M:%S',
                        level=logging.DEBUG)
    logging.info("start recording...")

    # self.logger = logging.getLogger('urbanGUI')
    main()
    # debug()
