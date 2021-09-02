# TP-Redes-Traceroute
    Com a utilização da biblioteca scapy, que faz a construção do cabeçalho do pacote, o projeto deve ser executado em modo root, no linux podemos colocar o comando sudo ao inicio da linha de comando. (Deve-se fazer uma reconfiguração no comando sudo para execução de todas as bibliotecas de forma correta)

    Reconfiguração do "sudo"
    
        $ sudo visudo
        
        Alterar a linha "Default   env_reset" para "Default   !env_reset"
        Comentar a linha "#Defaults       secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin""

        Pressione ctrl + O para salvar o arquivo Vi
        Pressione ctrl + X para fechar o arquivo Vi

        (Não recomendo fazer essa reconfiguração caso não tenha um conhecimento prévio sobre Linux. Faça por sua conta em risco.
        Não esqueça de voltar o arquivo para seu estado original quando terminar de testar o projeto, voltando as duas linhas alteradas ao que eram antes.)



    Após fazer as alterações nas configurações "sudo", você já pode rodar o script

    $ sudo python3 GeoIPLoc.py


    Este projeto contém algumas bibliotecas python em sua estrutura e APIs externas para seu funcionamento, abaixo há algumas instruções para a instalação dessas bibliotecas. Também contém o link para a API.
    
<~~~~ ## A API IPifoDB ## ~~~~>
A API de geolocalização consta com alguns requisitos para seu funcionamento, incluindo eles:
        
    A chave ID de cadastro -> f5ad2b83006363b9227f48569c02468389c49dd65363884ef06598945e9d187d
    O IP de origem deve ser o mesmo cadastrado -> Esse IP de origem foi cadastrado como o IP externo da VPN criada pelo Docente. 


<~~~~ ## IPs PARA TESTES ## ~~~~>
    IPs para teste:
        www.google.com      -> 8.8.8.8
        cpentalk.com        -> 104.21.11.36
        www.youtube.com     -> 142.251.128.14
        github.com          -> 20.201.28.151
        stackoverflow.com   -> 151.101.129.69
        
        

<~~~~~~~ ## CRIANDO AMBIENTE PYTHON ## ~~~~~~~>

        $ conda create --name nome_ambiente

<~~~~~~~~~~ ## ACESSANDO AMBIENTE ## ~~~~~~~~~>

        $ conda activate nome_ambiente


<~~~~~~~~ ## BIBLIOTECAS UTILIZADAS ## ~~~~~~~>

    Biblioteca Matplotlib (Gráfica)

        $ conda install -c conda-forge matplotlib


    Biblioteca Cartopy    (Gráfica)

        $ conda install -c conda-forge cartopy


    Biblioteca Scapy      (Criação de Pacotes)

        $ conda install -c conda-forge scapy


    Biblioteca requests   (Requisições externas)

        $ conda install -c conda-forge requests


<~~~~~º~~~~~ ## APIs UTILIZADAS ## ~~º~~~~~~~~>
    API geolocalização por IP, utilizada para fazer as requisições de localização do sistema

IPInfoDB -> https://www.ipinfodb.com/
