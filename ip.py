import requests
import pygeoip
from geolite2 import geolite2
import nmap

class Network(object):
    def _init_(self,ip=''):
        ip = input("Please Enter Default IP address of router")
        self.ip=ip
    def networkscanner(self):
        if len(self.ip)==0:
           network='192.168.1.1/24'
        else:
           network= self.ip +'/24'    
        print("Scanning Please wait ------->")

        nm=nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sn')
        hosts_list= [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hosts_list:
            print("Host\t{}".format(host))


D= Network()
D._init_()
D.networkscanner()


def get_ip_location(ip):
    reader = geolite2.reader()
    location =reader.get(ip)

    a=(location['city']['names']['en'])
    b=(location['continent']['names']['en'])
    c=(location['country']['names']['en'])
    d=(location['location'])
    e=(location['postal'])
    f=(location['registered_country']['names']['en'])

    print(a,b,c,d,e,f)

A=requests.get('http://api.ipify.org/').text

get_ip_location(A)