#!/usr/bin/env python3
"""A TCP SYN -- the first packet of every TCP connection.

The flags field is a set of named bits. "S" is SYN. Scapy prints flags by
their letters (S, A, SA for SYN+ACK, F for FIN, ...) and lets you set them
the same way.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP

syn = IP(dst="192.0.2.1") / TCP(sport=40000, dport=80, flags="S", seq=1000)

print(syn.summary())
syn.show()

print("flags as text :", syn[TCP].flags)
print("flags as bits :", int(syn[TCP].flags), "(bit 1 = SYN)")

# A SYN+ACK reply would set both bits:
synack = IP() / TCP(flags="SA")
print("\nA SYN+ACK would read:", synack[TCP].flags)
