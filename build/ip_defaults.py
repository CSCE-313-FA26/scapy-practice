#!/usr/bin/env python3
"""Build the simplest possible packet and look at what Scapy filled in.

You give Scapy a destination; it supplies a sane default for every other
field. `.show()` prints the whole packet as a tree so you can see those
defaults before any byte goes on the wire. Nothing here is sent, so it runs
without root.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP

pkt = IP(dst="192.0.2.1")        # 192.0.2.0/24 is the "TEST-NET" range (RFC 5737)

print("As a one-liner:")
print("  ", pkt.summary())

print("\nField by field (defaults Scapy chose are shown in the tree):")
pkt.show()

print("version =", pkt.version, "  ihl =", pkt.ihl, "  ttl =", pkt.ttl)
print("Scapy left ihl/len/chksum as None -- it computes them when the")
print("packet is serialised, not before.")
