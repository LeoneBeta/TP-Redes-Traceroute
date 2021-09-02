# coding: utf-8

from scapy.all import *
from requests import get
import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import matplotlib.ticker as mticker
import numpy as np

##Armazenando o link de requisição da API de localização, ja inserido a clientID de cadastro
apiLink = 'https://api.ipinfodb.com/v3/ip-city?key=f5ad2b83006363b9227f48569c02468389c49dd65363884ef06598945e9d187d&ip='

hostName = input("Forneça o IP/url: ")

##listLocation = [[]for j in range(50)] ##uma lista de listas para armazenar os dados
listLocation = []
location = []


jumps = 0
##Função traceroute com scapy, retorna os ips dos roteadores no caminho da origem até o destino fornecido,
##junto com a requisição de localização baseada em IP com a API 
for i in range(1, 100):
    pkt = IP(dst=hostName, ttl=i) / UDP(dport=33434)
    reply = sr1(pkt, verbose=0)
    if reply is None:
        break
    
    ##Faz a requisição da localização por IP na API IPInfoDB
    completeLink = apiLink + reply.src
    stringLocation = get(completeLink).text
    
    ##dividir a string e armazenar os dados na lista location
    location = stringLocation.split(';')

    ##armazena a lista location em uma lista, deixando todos os dados de localidade armazenados
    listLocation.append(location)
    jumps += 1
    if reply.type == 3:
        break
print("Traceroute Concluído\n\n")
print("Iniciando geração de mapa\n")
print("...\n")

'''
##Gerando o Mapa
fig = plt.figure(figsize=(20,15))

ax = fig.add_subplot(111, projection=ccrs.Robinson())

ax.add_feature(cfeature.LAND)
ax.add_feature(cfeature.OCEAN)
ax.add_feature(cfeature.COASTLINE)
ax.add_feature(cfeature.BORDERS)
ax.add_feature(cfeature.LAKES)
ax.add_feature(cfeature.RIVERS)

ax.stock_img()

ax.gridlines(ccrs.Robinson)
ax.set_title('GeoIPLoc',fontsize=20,y=1.02)
'''

fig = plt.figure(figsize=(10, 5))
ax = fig.add_subplot(1, 1, 1, projection=ccrs.Robinson())

# make the map global rather than have it zoom in to
# the extents of any plotted data
ax.set_global()

ax.stock_img()
ax.coastlines()


##Remove os IPs que não foi possível encontrar a localização por estarem ocultos
check=0
while jumps != 0:
    if listLocation[check][3] == '-':
        del listLocation[check]
    else:
        check += 1
    jumps -= 1

test = 1
while test != check:
    print(listLocation[test-1][9],listLocation[test-1][8]) 
    test += 1

##variáveis de controle
x=0
y=1
exit = 1

while exit != check:
    
    ##posições 8 e 9 longitude e latitude
    ##[segundo_valorx,segundo_valory],[primeiro_valorx,primeiro_valory] 
    ax.plot([listLocation[exit-1][9],listLocation[exit][9]],[listLocation[exit-1][8],listLocation[exit][8]], zorder = 100, transform=ccrs.PlateCarree())
    
    exit += 1
    
print("Mapa Gerado com sucesso")
plt.show()
'''
##Listar os dados de localização
print("---------------------------------------------------------------")
print("#  ID\t\t País\t    Estado\t\tCidade\t#")
print("---------------------------------------------------------------")
print("---------------------------------------------------------------")
print(listLocation[0][2],"\t\t\t\t\tIP de Origem")
print("---------------------------------------------------------------")

for k in listLocation:
    if k[3] != '-':      
        print ("{:<10} {:^10} {:>15} {:>20}".format(k[2],k[3],k[8],k[9]))
        print("---------------------------------------------------------------")

'''