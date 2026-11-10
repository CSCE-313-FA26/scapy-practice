#!/usr/bin/env python3
"""A packet is really just bytes. Here are those bytes.

  bytes(pkt)   the raw wire representation as a Python bytes object
  hexdump(pkt) the same bytes as an offset / hex / ASCII table

Serialising with bytes() is also the moment Scapy computes the lengths and
checksums it left as None while you were building.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, hexdump

pkt = IP(dst="192.0.2.1") / TCP(dport=80, flags="S")

raw = bytes(pkt)
print("len(bytes(pkt)) =", len(raw), "bytes  (20 IP header + 20 TCP header)")
print("first 4 bytes   =", raw[:4].hex(" "), " (45 = version 4, ihl 5; then TOS, total length)")
print("\nhexdump:")
hexdump(pkt)
