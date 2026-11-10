#!/usr/bin/env python3
"""Read a capture file back in and walk through the packets.

rdpcap(file) returns a list you can index and loop over. This is the reading
half of write_pcap.py, and the offline stand-in for a live sniff: the packets
are real, they just came from a file instead of a wire.
"""
import logging, os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, TCP

here = os.path.dirname(os.path.abspath(__file__))
packets = rdpcap(os.path.join(here, "sample.pcap"))

print(f"{len(packets)} packets in the capture:\n")
for i, p in enumerate(packets, 1):
    proto = p.sprintf("%IP.proto%") if IP in p else "?"
    print(f"   {i}. {p.summary()}")

print("\nFirst packet, in full:")
packets[0].show()
