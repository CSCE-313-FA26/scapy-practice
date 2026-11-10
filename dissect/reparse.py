#!/usr/bin/env python3
"""Serialise a packet to bytes, then hand those bytes back to Scapy.

This is exactly what a sniffer does: it receives raw bytes off the wire and
Scapy *dissects* them back into layers. Building then re-parsing proves the
round trip and shows that the parsed copy is structurally identical.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP

original = IP(dst="203.0.113.5", ttl=64) / TCP(dport=22, flags="S")
raw = bytes(original)                 # build -> wire bytes

parsed = IP(raw)                      # wire bytes -> layers again (dissection)

print("original :", original.summary())
print("parsed   :", parsed.summary())
print("\nParsed back out of the raw bytes:")
print("   dst   =", parsed.dst)
print("   ttl   =", parsed.ttl)
print("   dport =", parsed[TCP].dport)
print("   flags =", parsed[TCP].flags)
print("\nSame bytes after the round trip?", bytes(parsed) == raw)
