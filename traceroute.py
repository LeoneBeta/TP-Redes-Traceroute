# coding: utf-8

import socket
from scapy.all import *
from requests import get
##import cartopy.crs as ccrs
     
apiLink = 'https://api.ipinfodb.com/v3/ip-city?key=f5ad2b83006363b9227f48569c02468389c49dd65363884ef06598945e9d187d&ip='

hostName = input("Forneça o IP/url: ")


##listLocation = [[]for j in range(50)] ##uma lista de listas para armazenar os dados
listLocation = []
location = []

##Função traceroute com scapy, retorna os ips dos roteadores no caminho da origem até o destino fornecido
for i in range(1, 50):
    pkt = IP(dst=hostName, ttl=i) / UDP(dport=33434)
    reply = sr1(pkt, verbose=0)
    if reply is None:
        break
    
    ##Faz a requisição da localização por IP na API IPInfoDB
    completeLink = apiLink + reply.src
    stringLocation = get(completeLink).text
    
    ##dividir a string e armazenar os dados na lista location
    location = stringLocation.split(';')

    print(location)

    ##armazena a lista location em uma lista, assim criando uma lista de listas
    listLocation.append(location)


    if reply.type == 3:
        print("Chegou!")
        break

##lista listLocation armazena varias listas de localizações de cada ip coletado pelo traceroute


##utilizar os dados de localização numa API gráfica como, matplotlib e cartopy para gerar o mapa


