# coding: utf-8

import socket

serverPort = 15000
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket = bind(('',serverPort))
serverSocket.listen(0)

print("Servidor pronto para receber")

while true:
    