import os
import sys
import subprocess
import time
import platform
import re
import ipaddress
from datetime import datetime

startTime = time.time()

def scanPortRange(startPort, endPort):
    print(f'Port Number: {startPort} {endPort}')

def scanPortSingle(startPort):
    print(f'PortNumber: {startPort}')

def validateIP(ip):
    def validNums(s):
        try: return str(int(s)) == s and 0 <= int(s) <= 255
        except: return False

    if(ip.count(".") == 3 and all(validNums(i) for i in ip.split("."))):
        return True
    
    return False
    
def pingSingle(host):
    res = subprocess.call(['ping', '-c', '3', '-q', host])
    if (res == 0): 
            print( "Ping to", host, "OK") 
    elif (res == 2): 
        print("No response from", host) 
    else: 
        print("Ping to", host, "failed!")

def pingRange(startHost, endHost):
    ipRange = int(ipaddress.IPv4Address(endHost)) - int(ipaddress.IPv4Address(startHost))
    print(ipRange)
    address = ipaddress.IPv4Address(startHost)
    for ping in range(ipRange + 1):
        res = subprocess.call(['ping', '-c', '3', '-q', str(address)]) 
        if (res == 0): 
            print( "Ping to", address, "OK") 
        elif (res == 2): 
            print("No response from", address) 
        else: 
            print("Ping to", address, "failed!")

        address += 1

if len(sys.argv) > 1:
    for i in sys.argv:
        if(sys.argv[sys.argv.index(i)] == '-v'):
            print('version 0.1')

        elif(sys.argv[sys.argv.index(i)] == '-h'):
            print('sajdasd')

        elif(sys.argv[sys.argv.index(i)] == '-t'):
            print(time.time() - startTime)

        elif(sys.argv[sys.argv.index(i)] == '-p'):
            if (sys.argv[sys.argv.index(i) + 1].isnumeric()): 
                if(int(sys.argv[sys.argv.index(i) + 1]) >= 0 and int(sys.argv[sys.argv.index(i) + 1]) <= 65535):
                    startPort = int(sys.argv[sys.argv.index(i) + 1])

                    if(sys.argv.index(i) + 2 < len(sys.argv)): 
                        if(sys.argv[sys.argv.index(i) + 2].isnumeric()):
                            if(int(sys.argv[sys.argv.index(i) + 2]) >= 0 and int(sys.argv[sys.argv.index(i) + 2]) <= 65535 and int(sys.argv[sys.argv.index(i) + 2]) > startPort): 
                                endPort = int(sys.argv[sys.argv.index(i) + 2])
                                scanPortRange(startPort, endPort)
                            else:
                                scanPortSingle(startPort)
                    else:
                        scanPortSingle(startPort)
                else:
                    print("Invalid value for startPort")

            else:
                print("Invalid value for startPort")
        
        elif(sys.argv[sys.argv.index(i)] == 'host'):
            if(validateIP(sys.argv[sys.argv.index(i) + 1])):
                startHost = sys.argv[sys.argv.index(i) + 1]

                if(sys.argv.index(i) + 2 < len(sys.argv)): 
                    if(validateIP(sys.argv[sys.argv.index(i) + 2])):
                        endHost = sys.argv[sys.argv.index(i) + 2]
                        pingRange(startHost, endHost)
                    else:
                        pingSingle(startHost)
                else:
                    pingSingle(startHost)
            else:
                print("Invalid startHost IP address")
        