import os
import sys
import time
import ipaddress
from datetime import datetime
import nmap3
import tabulate

from nmap3.nmap3 import NmapHostDiscovery, NmapScanTechniques

startTime = time.time()
nmap = nmap3.Nmap()
port = 53
startHost = None
endHost = None

hostResults = []

def scanPort(port):
    print(f'Port Number: {port}')
    nmap = NmapScanTechniques()
    nmaphd = NmapHostDiscovery()

    for host in hostResults:
            tcpconn = nmap.nmap_tcp_scan(host["address"], args="-Pn -p " + str(port))
            if host["address"] in tcpconn:
                portList = tcpconn[host["address"]]["ports"]

                host.update({"tcp_conn": "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port):
                        print("yay")
                        host.update({"tcp_conn": tempPort["state"]})
            else:
                host.update({"tcp_conn": "closed"})

            tcpsyn = nmap.nmap_syn_scan(host["address"], args="-Pn -p " + str(port))
            if host["address"] in tcpsyn:
                portList = tcpsyn[host["address"]]["ports"]
                host.update({"tcp_syn": "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port):
                        print("yay(1)")
                        host.update({"tcp_syn" : tempPort["state"]})
            else:
                host.update({"tcp_syn": "closed"})

            tcpfin = nmap.nmap_fin_scan(host["address"], args="-Pn -p " + str(port))
            if host["address"] in tcpfin:
                portList = tcpfin[host["address"]]["ports"]
                host.update({"tcp_fin" : "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port):
                        print("yay(2)")
                        host.update({"tcp_fin" : tempPort["state"]})
            else:
                host.update({"tcp_fin" : "closed"})

            tcpxmas = nmaphd.nmap_portscan_only(host["address"], args="-sX -p " + str(port))
            if host["address"] in tcpxmas:
                portList = tcpxmas[host["address"]]["ports"]
                host.update({"tcp_xmas" : "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port):
                        print("yay(3)")
                        host.update({"tcp_xmas" : tempPort["state"]})
            else:
                host.update({"tcp_xmas" : "closed"})

            tcpnull = nmaphd.nmap_portscan_only(host["address"], args="-sN -p " + str(port))
            if host["address"] in tcpnull:
                portList = tcpnull[host["address"]]["ports"]
                host.update({"tcp_null" : "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port):
                        print("yay(4)")
                        host.update({"tcp_null" : tempPort["state"]})
            else:
                host.update({"tcp_null" : "closed"})

            tcpack = nmaphd.nmap_portscan_only(host["address"], args="-sA -p " + str(port))
            if host["address"] in tcpack:
                portList = tcpack[host["address"]]["ports"]
                host.update({"tcp_ack" : "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port):
                        print("yay(5)")
                        host.update({"tcp_ack" : tempPort["state"]})
            else:
                host.update({"tcp_ack" : "closed"})
    
#   print(hostResults)

def printTable():
    print("Target Port: ", port)
    header = ["Address", "ICMP", "CONN", "SYN", "FIN", "Xmas", "Null", "ACK"]
    rows = [i.values() for i in hostResults]
    print(tabulate.tabulate(rows, header, tablefmt="grid"))
            

def validateIP(ip):
    def validNums(s):
        try: return str(int(s)) == s and 0 <= int(s) <= 255
        except: return False

    if(ip.count(".") == 3 and all(validNums(i) for i in ip.split("."))):
        return True
    
    return False
    
def pingSingle(host, port):
    print("Host: ", host)
    nmap = nmap3.NmapHostDiscovery()
    result = nmap.nmap_no_portscan(host)

    if host in result:
        hostResults.append({'address': host, 'state': result[host]["state"]["state"]})
        scanPort(port)

def pingRange(startHost, endHost, port):
    print("Start Host: ", startHost)
    print("End Host: ", endHost)
    nmap = nmap3.NmapHostDiscovery()
    ipRange = int(ipaddress.IPv4Address(endHost)) - int(ipaddress.IPv4Address(startHost))
    print(ipRange)
    address = ipaddress.IPv4Address(startHost)
    for i in range(ipRange + 1):
        result = nmap.nmap_no_portscan(str(address))
        if str(address) in result: 
            hostResults.append({'address':str(address), 'state': result[str(address)]["state"]["state"]})
        else:
            hostResults.append({'address':str(address), 'state': 'down'})

        address += 1

    scanPort(port)

if len(sys.argv) > 1:
    for i in sys.argv:
        if(sys.argv[sys.argv.index(i)] == '-v'):
            print('version 0.1')

        if(sys.argv[sys.argv.index(i)] == '-h'):
            print('sajdasd')

        if(sys.argv[sys.argv.index(i)] == '-t'):
            print(time.time() - startTime)

        if(sys.argv[sys.argv.index(i)] == '-p'):
            if (sys.argv[sys.argv.index(i) + 1].isnumeric()): 
                if(int(sys.argv[sys.argv.index(i) + 1]) >= 0 and int(sys.argv[sys.argv.index(i) + 1]) <= 65535):
                    port = int(sys.argv[sys.argv.index(i) + 1])
                else:
                    print("Invalid port number")
            else:
                print("Invalid port number")
        
        if(sys.argv[sys.argv.index(i)] == 'host'):
            if(validateIP(sys.argv[sys.argv.index(i) + 1])):
                startHost = sys.argv[sys.argv.index(i) + 1]

                if(sys.argv.index(i) + 2 < len(sys.argv)): 
                    if(validateIP(sys.argv[sys.argv.index(i) + 2])):
                        endHost = sys.argv[sys.argv.index(i) + 2]
            else:
                print("Invalid startHost IP address")

if startHost is not None:
    if endHost is not None:
        pingRange(startHost, endHost, port)
    else:
        pingSingle(startHost, port)
        