# TP-Redes-Traceroute
    Com a utilização da biblioteca scapy, que faz a construção do cabeçalho do pacote, o projeto deve ser 
executado em modo root, no linux podemos colocar o comando sudo ao inicio da linha de comando.
    
    $ sudo python3 GeoIPLoc.py

    Este projeto contém algumas bibliotecas python em sua estrutura e APIs externas para seu funcionamento,
abaixo há algumas instruções para a instalação dessas bibliotecas. Também contém o link para a API.
    
<~~~~ ## A API IPifoDB ## ~~~~>
A API de geolocalização consta com alguns requisitos para seu funcionamento, incluindo eles:
        
    A chave ID de cadastro -> f5ad2b83006363b9227f48569c02468389c49dd65363884ef06598945e9d187d
    O IP de origem deve ser o mesmo cadastrado -> Esse IP de origem foi cadastrado como o IP externo
da VPN criada pelo Docente. 


<~~~~ ## IPs PARA TESTES ## ~~~~>
    IPs para teste:
        www.google.com -> 8.8.8.8
        www.youtube.com -> 142.251.128.14
        www.instagram.com -> 157.240.222.174
        www.globo.com -> 186.192.81.5
        


<~~~~ ## CRIANDO AMBIENTE PYTHON ## ~~~~>

    conda create --name nome_ambiente

<~~~~ ## ACESSANDO AMBIENTE ## ~~~~>

    conda activate nome_ambiente


<~~~~ ## BIBLIOTECAS UTILIZADAS ## ~~~~>

Biblioteca Matplotlib
    conda install -c conda-forge matplotlib
Biblioteca Cartopy
    conda install -c conda-forge cartopy
Biblioteca Scapy
    conda install -c conda-forge scapy
Biblioteca requests
    conda install -c conda-forge requests

<~~~~~~ ## APIs UTILIZADAS ## ~~~~~~>
    API geolocalização por IP, utilizada para fazer as requisições de localização do sistema

IPInfoDB -> https://www.ipinfodb.com/
