# coding: utf-8

import socket
from scapy.all import *

##serverPort = 16000  #Porta de leitura
##serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
##serverSocket.bind(('', serverPort))
##serverSocket.listen(0)
     
hostName = input("Forneça o IP: ")
##Função traceroute com scapy
for i in range(1, 28):
    pkt = IP(dst=hostName, ttl=i) / UDP(dport=33434)
    reply = sr1(pkt, verbose=0)
    if reply is None:
        break
    elif reply.type == 3:
        print("Done!", reply.src)
        break
    else:
        print("%d hops away: " % i, reply.src)


##Função de PING
##def myping(host):
##    parameter = '-n' if platform.system().lower()=='windows' else '-c'

##    command = ['ping', parameter, '1', host]
##    response = subprocess.call(command)

    ##if response == 0:
    ##    return True
    ##else:
    ##    return False

##connectionSocket.close()
