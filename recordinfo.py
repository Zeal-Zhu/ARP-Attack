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
            # getimg(pdata)
            getinfo(pdata)
            # getresponse(pdata)
    else:
        parser.print_help()
        sys.exit(0)


def getresponse(pdata):
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


def getinfo(pdata):
    global urllist
    p = dpkt.ethernet.Ethernet(pdata)
    ipdata = p.data
    tcpdata = p.data.data
    if len(tcpdata.data) > 0 and ipdata.__class__.__name__ == 'IP' and tcpdata.__class__.__name__ == 'TCP' and tcpdata.dport == 80:
        # pa = re.compile(r'GET (.*?)')
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


def getimg(pdata):
    global imgurllist
    p=dpkt.ethernet.Ethernet(pdata)
    if p.data.__class__.__name__ == 'IP' and p.data.data.__class__.__name__ == 'TCP' and p.data.data.dport == 80:
        logging.info("get url: "+p.data.data.data)
        pa=re.compile(r'GET (.*?\.jpg)')  # |.*?\.png|.*?\.gif
        img=re.findall(pa, p.data.data.data)
        if img != []:
            lines=p.data.data.data.split('\n')
            for line in lines:
                if 'Host:' in line:
                    url='http://'+line.split(':')[-1].strip()+img[-1]
                    if url not in imgurllist:
                        imgurllist.append(url)
                        if 'Referer:' in p.data.data.data:
                            for line in lines:
                                if 'Referer:' in line:
                                    referer="http:" + \
                                        line.split(':')[-1].strip()
                                    logging.info("img url: "+url)
                                    print "url: "+url
                                    try:
                                        r=requests.get(
                                            url, headers={'Referer': referer})
                                        img=Image.open(BytesIO(r.content))
                                        img.show()
                                    except IOError as e:
                                        print e
                                        pass

                        else:
                            r=requests.get(url)
                            img=Image.open(BytesIO(r.content))
                            img.show()
                    else:
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
