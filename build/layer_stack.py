#!/usr/bin/env python3
"""The `/` operator stacks one protocol layer on top of another.

Ether / IP / TCP / Raw is a packet with a link, network, transport and
payload layer. `/` is 'encapsulate': the left layer carries the right one.
Read it outside-in, exactly like the bytes go on the wire.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, Raw

frame = Ether() / IP(dst="192.0.2.1") / TCP(dport=80) / Raw(b"GET / HTTP/1.0\r\n\r\n")

print("summary():", frame.summary())
print("\nThe layers, outermost first:")
layer = frame
while layer:
    print("   ", layer.__class__.__name__)
    layer = layer.payload if layer.payload else None

print("\nScapy set each layer's 'type'/'proto' field to match the next layer up:")
print("   Ether.type =", hex(frame[Ether].type), "(0x0800 = IPv4)")
print("   IP.proto   =", frame[IP].proto, "(6 = TCP)")
