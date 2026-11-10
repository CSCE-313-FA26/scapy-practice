#!/usr/bin/env python3
"""Read a packet, change a field, write it back -- manipulation, offline.

This is the heart of 'packet manipulation': you do not have to build every
packet from nothing. Read one that exists, alter a field (here the TTL), and
Scapy recomputes the checksum for you when it re-serialises. No root needed,
because we read from and write to files, not an interface.
"""
import logging, os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, wrpcap, IP

here = os.path.dirname(os.path.abspath(__file__))
pkt = rdpcap(os.path.join(here, "sample.pcap"))[0]     # the ping

print("Before:")
print("   dst =", pkt[IP].dst, " ttl =", pkt[IP].ttl, " chksum =", hex(pkt[IP].chksum))

pkt[IP].ttl = 7                 # change a field
del pkt[IP].chksum              # drop the now-stale checksum so Scapy recomputes

fixed = IP(bytes(pkt[IP]))      # re-serialise + re-parse to get the new checksum
print("\nAfter changing ttl to 7:")
print("   dst =", fixed.dst, " ttl =", fixed.ttl, " chksum =", hex(fixed.chksum),
      " (recomputed -- different from before)")

out = os.path.join(here, "modified.pcap")
wrpcap(out, pkt)
print(f"\nWrote the modified packet to {out}")
