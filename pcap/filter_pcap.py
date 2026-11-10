#!/usr/bin/env python3
"""Pick packets out of a capture by what is inside them.

A capture is just a Python list, so you filter it with ordinary list
comprehensions and Scapy's layer tests. Below: every TCP SYN (SYN set,
ACK not), and every DNS question.
"""
import logging, os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, TCP, DNS, DNSQR

here = os.path.dirname(os.path.abspath(__file__))
packets = rdpcap(os.path.join(here, "sample.pcap"))

syns = [p for p in packets if TCP in p and p[TCP].flags == "S"]
print(f"TCP SYN packets ({len(syns)}):")
for p in syns:
    print(f"   {p[IP].src} -> {p[IP].dst}:{p[TCP].dport}")

dns = [p for p in packets if DNS in p and p[DNS].qd is not None]
print(f"\nDNS questions ({len(dns)}):")
for p in dns:
    print(f"   asking for {p[DNSQR].qname.decode()}")
