#!/usr/bin/env python3
"""Reach into a packet by layer and by field.

  pkt[TCP]          the TCP layer
  pkt[TCP].dport    one field of it
  TCP in pkt        is that layer present?
  pkt.haslayer(..)  same question, method form
  pkt.payload       everything below the current layer
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, Raw

pkt = Ether() / IP(dst="192.0.2.1", src="192.0.2.9") / TCP(dport=80) / Raw(b"payload")

print("pkt[IP].src   =", pkt[IP].src)
print("pkt[IP].dst   =", pkt[IP].dst)
print("pkt[TCP].dport=", pkt[TCP].dport)

print("\nIs there a TCP layer?   ", TCP in pkt)
print("Is there a UDP layer?   ", pkt.haslayer('UDP'))

print("\nWalk down with .payload:")
print("   IP payload  ->", pkt[IP].payload.summary())
print("   TCP payload ->", pkt[TCP].payload.summary(), "(the Raw bytes)")
print("   Raw load    ->", pkt[Raw].load)
