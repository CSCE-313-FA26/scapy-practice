#!/usr/bin/env python3
"""A DNS query packet: 'what is the A record for example.com?'

DNS rides on UDP port 53. The question is a DNSQR (DNS Question Record).
Nothing is sent here -- we build the query and then read the name back out,
to show a query is just structured bytes like any other packet.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, UDP, DNS, DNSQR

query = IP(dst="8.8.8.8") / UDP(sport=50000, dport=53) / DNS(
    rd=1,                                   # rd = recursion desired
    qd=DNSQR(qname="example.com", qtype="A")
)

query.show()
print("Transport  :", "UDP/53")
print("rd (recursion desired) =", query[DNS].rd)
print("Question   :", query[DNSQR].qname.decode(), "type", query[DNSQR].qtype)
