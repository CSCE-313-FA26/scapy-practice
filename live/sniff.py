#!/usr/bin/env python3
"""Read packets as they arrive.  Live sniffing REQUIRES ROOT -- but sniff()
can also read a capture FILE, and that runs for everyone.

  sniff(iface=..., prn=cb)          live capture -- needs root
  sniff(offline="file.pcap", prn=cb) read a saved capture -- no root

The callback (prn) is called once per packet. The two modes call it exactly
the same way, so you develop and test your packet-handling code against a
file, then switch to a live interface only when you actually have privilege.
"""
import logging, os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP

def show_pkt(pkt):
    if IP in pkt:
        print(f"   {pkt[IP].src} -> {pkt[IP].dst}   {pkt.summary()}")

here = os.path.dirname(os.path.abspath(__file__))
sample = os.path.join(here, "..", "pcap", "sample.pcap")

print("Reading from the saved capture (no root needed):")
sniff(offline=sample, prn=show_pkt, store=False)

print("\nTo sniff a live interface instead (needs root):")
print("   sudo python3 -c \"from scapy.all import sniff; sniff(prn=lambda p: p.summary(), count=5)\"")
