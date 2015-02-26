from pygeoip import *
import socket

'''
gleeda
jamie.levy@gmail.com

Will fix this up later, but quick and dirty way to get a report on some IP addresses
'''

ipfile = "ips_sorted.txt"
#excelfile = "output.xlsx"
robtex = "https://www.robtex.com/en/advisory/ip"
GeoLite = "GeoLiteCity.dat"

f = open(ipfile, "r")
gi = GeoIP(GeoLite)

codes = {
    "127.0.0.2": "Direct UBE sources, spam operations & spam services",
    "127.0.0.3": "Direct snowshoe spam sources detected via automation",
    "127.0.0.4": "CBL (3rd party exploits such as proxies, trojans, etc.)",
    "127.0.0.5": "CBL (3rd party exploits such as proxies, trojans, etc.)",
    "127.0.0.6": "CBL (3rd party exploits such as proxies, trojans, etc.)",
    "127.0.0.7": "CBL (3rd party exploits such as proxies, trojans, etc.)",
    "127.0.0.10": "End-user Non-MTA IP addresses set by ISP outbound mail policy",
    "127.0.0.11": "End-user Non-MTA IP addresses set by ISP outbound mail policy",
}

servers = [
    "sbl-xbl.spamhaus.org",
    "xbl.spamhaus.org",
    "cbl.abuseat.org",
]

def checkbl(ip):
    for server in servers:
        try:
            res = socket.gethostbyname(ip + '.' + server)
            return "Yes"
        except socket.gaierror:
            pass
    return ""

for i in f.readlines():
    item =  i.strip()
    rev = '.'.join(item.split('.')[::-1])
    stuff = gi.record_by_addr(item)
    ip = "/".join(item.split("."))
    robtex_url = "{0}/{1}".format(robtex, ip)
    print "{0},{1},{2},{3},{4}".format(item, stuff["country_code"], stuff["country_name"], robtex_url, checkbl(rev))
