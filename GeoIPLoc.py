# coding: utf-8

from scapy.all import *
from requests import get
import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import math

##Armazenando o link de requisição da API de localização, ja inserido a clientID de cadastro
apiLink = 'https://api.ipinfodb.com/v3/ip-city?key=f5ad2b83006363b9227f48569c02468389c49dd65363884ef06598945e9d187d&ip='

hostName = input("Forneça o IP/url: ")

##Listas utilizadas para armazenar os dados de localização
listLocation = []
location = []


jumps = 0
##Função traceroute com scapy, retorna os ips dos roteadores no caminho da origem até o destino fornecido,
##junto com a requisição de localização baseada em IP com a API 
for i in range(1, 100):
    pkt = IP(dst=hostName, ttl=i) / UDP(dport=33434)    ##Porta UDP préviamente inserida
    reply = sr1(pkt, verbose=0)     ##sr1 envia os pacotes gerados, verbose=0 impede que retorne algum tipo de texto
    if reply is None:     ##Valida se o pacote n foi perdido, ou houve algum erro
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
print("\x1b[2J")
print("Traceroute Concluído\n\n")
print("Iniciando geração de mapa\n")
print("...\n")


##Gera o mapa global, passando tamanho, estilo, e algumas configurações extras
fig = plt.figure(figsize=(20, 15))
ax = fig.add_subplot(1, 1, 1, projection=ccrs.Robinson())


ax.set_global()

##Plota o fundo estilizado, e marcações de divisa de países
ax.stock_img()
ax.coastlines()

ax.set_title('GeoIPLoc',fontsize=20,y=1.02)

print("\x1b[2J")
print("...")
##Remove os IPs que não foi possível encontrar a localização por estarem ocultos
check=0
while jumps != 0:
    if listLocation[check][3] == '-':
        del listLocation[check]
    else:
        check += 1
    jumps -= 1

##Convertendo a string para float, em seguida de float para int para ser utilizada na função de traçagem de rota
convert=0
while convert != check:
    listLocation[convert][8] = float(listLocation[convert][8]) 
    listLocation[convert][9] = float(listLocation[convert][9])

    listLocation[convert][8] = math.floor(listLocation[convert][8])
    listLocation[convert][9] = math.floor(listLocation[convert][9])

    convert += 1

##Plota a primeira coordenada marcada
ax.plot([-48,listLocation[0][9]],[-19,listLocation[0][8]],color='red',transform=ccrs.PlateCarree())
print("\x1b[2J")
print("...")
##Faz a plotagem de traçado dos IPs, coleta os dados de latitude e longitude anteriormente convertidos para int, para traçar as rotas
exit = 1
while exit != check:
    ##[segundo_valorx,segundo_valory],[primeiro_valorx,primeiro_valory] 
    ##print("Conexão",exit,": ",listLocation[exit-1][9],listLocation[exit-1][8],"|",listLocation[exit][9],listLocation[exit][8])
    ax.plot([listLocation[exit-1][9],listLocation[exit][9]],[listLocation[exit-1][8],listLocation[exit][8]], color='red', transform=ccrs.PlateCarree())
    exit += 1


print("Mapa Gerado com Sucesso!")
plt.show()

