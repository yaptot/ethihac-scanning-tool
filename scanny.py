import os
import sys
import time
import ipaddress
import nmap3
import tabulate
import signal

from nmap3.nmap3 import NmapHostDiscovery, NmapScanTechniques

startTime = time.time()
nmap = nmap3.Nmap()
port = 53
startHost = None
endHost = None
timecheck = False

hostResults = []

#   This function performs the port scans namely:
#       -TCP Connect
#       -TCP SYN
#       -TCP FIN
#       -Xmas
#       -Null
#       -TCP ACK
#   @params none
def scanPort():
    nmap = NmapScanTechniques()
    nmaphd = NmapHostDiscovery()

    for host in hostResults: #For loop to scan every host
            tcpconn = nmap.nmap_tcp_scan(host["address"], args="-Pn -p " + str(port)) #Command for TCP Connect scan
            if host["address"] in tcpconn:
                portList = tcpconn[host["address"]]["ports"]

                host.update({"tcp_conn": "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port): #Checks if the port was scanned
                        #print("yay")
                        host.update({"tcp_conn": tempPort["state"]}) #Stores the status of the port
            else:
                host.update({"tcp_conn": "closed"})

            tcpsyn = nmap.nmap_syn_scan(host["address"], args="-Pn -p " + str(port)) #Command for SYN scan
            if host["address"] in tcpsyn:
                portList = tcpsyn[host["address"]]["ports"]
                host.update({"tcp_syn": "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port): #Checks if the port was scanned
                        #print("yay(1)")
                        host.update({"tcp_syn" : tempPort["state"]}) #Stores the status of the port
            else:
                host.update({"tcp_syn": "closed"})

            tcpfin = nmap.nmap_fin_scan(host["address"], args="-Pn -p " + str(port)) #Command for FIN scan
            if host["address"] in tcpfin:
                portList = tcpfin[host["address"]]["ports"]
                host.update({"tcp_fin" : "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port): #Checks if the port was scanned
                        #print("yay(2)")
                        host.update({"tcp_fin" : tempPort["state"]}) #Stores the status of the port
            else:
                host.update({"tcp_fin" : "closed"})

            tcpxmas = nmaphd.nmap_portscan_only(host["address"], args="-sX -p " + str(port)) #Command for Xmas scan
            if host["address"] in tcpxmas:
                portList = tcpxmas[host["address"]]["ports"]
                host.update({"tcp_xmas" : "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port): #Checks if the port was scanned
                        #print("yay(3)")
                        host.update({"tcp_xmas" : tempPort["state"]}) #Stores the status of the port
            else:
                host.update({"tcp_xmas" : "closed"})

            tcpnull = nmaphd.nmap_portscan_only(host["address"], args="-sN -p " + str(port)) #Command for Null scan
            if host["address"] in tcpnull:
                portList = tcpnull[host["address"]]["ports"]
                host.update({"tcp_null" : "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port): #Checks if the port was scanned
                        #print("yay(4)")
                        host.update({"tcp_null" : tempPort["state"]}) #Stores the status of the port
            else:
                host.update({"tcp_null" : "closed"})

            tcpack = nmaphd.nmap_portscan_only(host["address"], args="-sA -p " + str(port)) #Command for ACK scan
            if host["address"] in tcpack:
                portList = tcpack[host["address"]]["ports"]
                host.update({"tcp_ack" : "closed"})
                for tempPort in portList:
                    if tempPort["portid"] == str(port): #Checks if the port was scanned
                        #print("yay(5)")
                        host.update({"tcp_ack" : tempPort["state"]}) #stores the status of the port
            else:
                host.update({"tcp_ack" : "closed"})
            
    printTable()
    
#   print(hostResults)

#   This function tabulates and prints the results of the host and port scan.
#   @params none
def printTable():
    print("scanny.py".center(100))
    print("-------------------".center(100))
    print(("Port " + str(port)).center(100))
    header = ["Address", "ICMP", "CONN", "SYN", "FIN", "Xmas", "Null", "ACK"]
    rows = [i.values() for i in hostResults]
    print(tabulate.tabulate(rows, header, tablefmt="grid"))
            
#   This function validates the IP Address input by the user.
#   @params ip - the IP Address to be checked
#   @return True if the IP Address is valid
#           False if the IP Address is invalid
def validateIP(ip):
    def validNums(s):
        try: return str(int(s)) == s and 0 <= int(s) <= 255 #Checks if the numbers in each segment of the IP Address is between 0 and 255
        except: return False

    if(ip.count(".") == 3 and all(validNums(i) for i in ip.split("."))): #Checks if the IP Address is valid
        return True
    
    return False

#   This function performs the ICMP scan of a single host.
#   @params host - the host IP address to be scanned.    
def pingSingle(host):
    print("Host: ", host)
    nmap = nmap3.NmapHostDiscovery()
    result = nmap.nmap_no_portscan(host, args="-PE") #Command for ICMP scan

    if host in result:
        hostResults.append({'address': host, 'state': result[host]["state"]["state"]}) #Stores the host IP Address and its state using ICMP Scan
    else:
        hostResults.append({'address': host, 'state': "down"}) #Stores the host IP Address and its state using ICMP Scan
    
    scanPort()

#   This function performs the ICMP scan of a range of hosts
#   @params none
def pingRange():
    print("Start Host: ", startHost)
    print("End Host: ", endHost)
    nmap = nmap3.NmapHostDiscovery()
    ipRange = int(ipaddress.IPv4Address(endHost)) - int(ipaddress.IPv4Address(startHost)) #Gets the range of the IP Addresses to be scanned
    address = ipaddress.IPv4Address(startHost)
    for i in range(ipRange + 1): #For loop to scan all hosts within the range of IP Addresses provided
        result = nmap.nmap_no_portscan(str(address), args="-PE") #Command for ICMP Scan
        if str(address) in result: 
            hostResults.append({'address':str(address), 'state': result[str(address)]["state"]["state"]}) #Stores the host IP Address and its state using ICMP Scan
        else:
            hostResults.append({'address':str(address), 'state': 'down'}) #Stores the host IP Address and its state as down if there is an error

        address += 1

    scanPort()

#   This function prints the contents of the '-v' argument.
#   @params none
def printInfo():
    print('v1.0 created by Rupert Myles B. Yap')
    print('scanny.py is a Linux simple network scanning tool created using Python 3 and nmap. It can perform the following scans:')
    print('- ICMP Scan', '- TCP-Connect Scan', '- TCP SYN Scan', '- TCP FIN Scan', '- Xmas Scan', '- Null Scan', '- TCP ACK Scan', sep="\n", end="\n\n")

    print('The following are the pre-requisites for running scanny.py:')
    print('- Python 3', '- Nmap', '- Administrator/Root Privileges', sep="\n", end="\n\n")

    print('Please install all of the required Python 3 modules using sudo pip3 install -r requirements.txt')
    print('The requirements.txt file must be in the same folder with the program.\n')

    print('The github repository can be found in https://github.com/yaptot/ethihac-scanning-tool')

#   This function prints the contents of the '-h' argument.
#   @params none
def printHelp():
    print('scanny.py Usage:')
    print('sudo python3 scanny.py host <host IP address> <end host IP address (optional)> -p <port number>')
    print('Example: sudo python3 scanny.py host 10.10.0.11 10.10.0.12 -p 22\n')

    print('Options:')
    print('-h', 'View help.', sep="\t", end="\n\n")
    print('host', 'Add a host or a range of hosts (can only be used once). \n\thost <host IP Address> <end host IP address (optional)>', sep='\t', end="\n\n")
    print('-p', 'Specify a port number to be scanned. The default port number is 53. \n\t-p <port number>', sep='\t', end="\n\n")
    print('-t', 'Measure the time taken for the program to complete scanning (optional).', sep="\t", end="\n\n")
    print('-v', 'Version/About scanny.py', sep="\t")

def signalHandler(sig, frame):
    print('Exiting scanny.py')
    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

if len(sys.argv) > 1: #Checks the arguments of the command inputted
    for i in sys.argv:
        if(sys.argv[sys.argv.index(i)] == '-v'):
            printInfo()

        if(sys.argv[sys.argv.index(i)] == '-h'):
            printHelp()

        if(sys.argv[sys.argv.index(i)] == '-t'):
            timecheck = True

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
        pingRange()
    else:
        pingSingle(startHost)
    
if timecheck:
    print('Time taken:',time.time() - startTime, 'seconds')
