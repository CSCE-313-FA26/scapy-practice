#!/usr/bin/env python3
"""Let Scapy compute checksums and lengths for you.

While you build, Scapy leaves len/chksum as None. It fills them in when the
packet is serialised. If you change a field and want fresh values, delete the
stale ones (del pkt.chksum) and serialise again -- never hand-edit them.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP

pkt = IP(dst="192.0.2.1") / TCP(dport=80, flags="S")

print("Before serialising -- Scapy has not computed these yet:")
print("   IP.len    =", pkt.len)
print("   IP.chksum =", pkt.chksum)
print("   TCP.chksum=", pkt[TCP].chksum)

# Serialising computes them; re-parse so we can read the computed values back.
computed = IP(bytes(pkt))
print("\nAfter serialising (read back from the wire bytes):")
print("   IP.len    =", computed.len)
print("   IP.chksum =", hex(computed.chksum))
print("   TCP.chksum=", hex(computed[TCP].chksum))

# Now change the destination and show the checksum must be recomputed.
pkt.dst = "198.51.100.200"
del pkt.chksum                  # drop the stale value so Scapy recomputes
del pkt[TCP].chksum
recomputed = IP(bytes(pkt))
print("\nAfter changing dst and deleting the old checksums:")
print("   IP.chksum =", hex(recomputed.chksum), " (different -- the header changed)")
