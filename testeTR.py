# coding: utf-8

from scapy.all import *
hostname = "8.8.8.8"
for i in range(1, 28):
    pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
    reply = sr1(pkt, verbose=0)
    if reply is None:
        break
    elif reply.type == 3:
        print("Done!", reply.src)
        break
    else:
        print("%d hops away: " % i, reply.src)