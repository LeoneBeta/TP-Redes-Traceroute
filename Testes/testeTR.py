# coding: utf-8

import socket
from scapy.all import *
from requests import get
##import cartopy.crs as ccrs
     
apiLink = 'https://api.ipinfodb.com/v3/ip-city?key=f5ad2b83006363b9227f48569c02468389c49dd65363884ef06598945e9d187d&ip='

hostName = input("Forneça o IP/url: ")

##Função traceroute com scapy, retorna os ips dos roteadores no caminho da origem até o destino fornecido
for i in range(1, 50):
    pkt = IP(dst=hostName, ttl=i) / UDP(dport=33434)
    reply = sr1(pkt, verbose=0)
    if reply is None:
        break
    
    completeLink = apiLink + reply.src
    stringLocation = get(completeLink).text
    print(stringLocation)
    completeLink = 0

    if reply.type == 3:
        print("Chegou!")
        break

    ##variavel stringLocation armazena uma string com todos os dados de localização separados por ";"

    ##utilizar os dados de localização numa API gráfica como, matplotlib e cartopy para gerar o mapa




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
