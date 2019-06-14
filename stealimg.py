import pcap
import dpkt
import re
import requests
from PIL import Image
from io import BytesIO
from optparse import OptionParser
import sys

urllist = []


def main():
    usage = "Usage: [-i interface]"
    parser = OptionParser(usage)
    parser.add_option('-i', dest='interface',
                      help='select interface(input eth0 or wlan0 or more)')
    (options, args) = parser.parse_args()
    if options.interface:
        interface = options.interface
        pc = pcap.pcap(interface)
        pc.setfilter('tcp port 80')
        for ptime, pdata in pc:
            getimg(pdata)
    else:
        parser.print_help()
        sys.exit(0)


def getimg(pdata):
    global urllist
    p = dpkt.ethernet.Ethernet(pdata)
    if p.data.__class__.__name__ == 'IP':
        if p.data.data.__class__.__name__ == 'TCP':
            if p.data.data.dport == 80:
                pa = re.compile(r'GET (.*?\.jpg)')  # |.*?\.png|.*?\.gif
                img = re.findall(pa, p.data.data.data)
                print pa
                if img != []:
                    lines = p.data.data.data.split('\n')
                    for line in lines:
                        if 'Host:' in line:
                            url = 'http://'+line.split(':')[-1].strip()+img[-1]
                            if url not in urllist:
                                urllist.append(url)
                                if 'Referer:' in p.data.data.data:
                                    for line in lines:
                                        if 'Referer:' in line:
                                            referer = line.split(
                                                ':')[-1].strip()
                                            print url
                                            r = requests.get(
                                                url, headers={'Referer': referer})
                                            img = Image.open(
                                                BytesIO(r.content))
                                            img.show()
                                else:
                                    r = requests.get(url)
                                    img = Image.open(BytesIO(r.content))
                                    img.show()
                            else:
                                pass


if __name__ == '__main__':
    main()
