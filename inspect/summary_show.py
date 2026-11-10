#!/usr/bin/env python3
"""Three ways to look at a packet, from terse to verbose.

  .summary()  one line  -- what is this packet, at a glance
  .show()     a tree    -- every field, every layer
  repr(pkt)   the Scapy expression that would rebuild it
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Raw

pkt = IP(dst="192.0.2.1", ttl=42) / TCP(sport=1234, dport=80, flags="S") / Raw(b"hi")

print("summary():")
print("   ", pkt.summary())
print("\nrepr():")
print("   ", repr(pkt))
print("\nshow():")
pkt.show()
