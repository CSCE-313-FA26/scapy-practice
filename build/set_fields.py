#!/usr/bin/env python3
"""Two ways to set a field, and they are interchangeable.

You can pass fields to the constructor, or assign them as attributes after
the packet is built. Pick whichever reads better. Below builds the same
packet both ways and proves the wire bytes are identical.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP

# (a) constructor keyword arguments
a = IP(dst="192.0.2.9", ttl=16) / TCP(dport=443, flags="S")

# (b) build the layers first, then assign fields by attribute
b = IP() / TCP()
b.dst = "192.0.2.9"
b.ttl = 16
b[TCP].dport = 443
b[TCP].flags = "S"

print("(a) ", a.summary())
print("(b) ", b.summary())
print("\nttl   :", a.ttl, "==", b.ttl)
print("dst   :", a.dst, "==", b.dst)
print("dport :", a[TCP].dport, "==", b[TCP].dport)
print("flags :", a[TCP].flags, "==", b[TCP].flags, " ('S' is the SYN bit)")
print("\nSame wire bytes?", bytes(a) == bytes(b))
