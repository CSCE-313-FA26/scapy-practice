#!/usr/bin/env python3
"""Craft a handful of packets and save them to a .pcap capture file.

wrpcap(file, packets) writes a capture Wireshark, tcpdump or Scapy can read
later. Writing a file needs no special privilege, so this is how you practise
'capturing' traffic without a live interface or root. It (re)creates the
sample.pcap the other pcap/ examples read.

The Ethernet addresses are set explicitly (02:... = locally administered) so
the capture is the same on every machine -- an empty Ether() would fill in
whatever real MAC your interface happens to have.
"""
import logging, os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap

CLIENT_MAC = "02:00:00:00:00:06"
SERVER_MAC = "02:00:00:00:00:05"
E_OUT = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
E_IN  = Ether(src=SERVER_MAC, dst=CLIENT_MAC)

packets = [
    E_OUT/IP(src="10.9.0.6", dst="10.9.0.5")/ICMP(),                          # a ping
    E_OUT/IP(src="10.9.0.6", dst="10.9.0.5")/TCP(sport=40001, dport=80, flags="S"),
    E_IN /IP(src="10.9.0.5", dst="10.9.0.6")/TCP(sport=80, dport=40001, flags="SA"),
    E_OUT/IP(src="10.9.0.6", dst="8.8.8.8")/UDP(sport=50000, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")),
    E_OUT/IP(src="10.9.0.6", dst="10.9.0.5")/TCP(sport=40002, dport=22, flags="S")/Raw(b"ssh-probe"),
]

here = os.path.dirname(os.path.abspath(__file__))
out = os.path.join(here, "sample.pcap")
wrpcap(out, packets)
print(f"Wrote {len(packets)} packets to {out}")
for i, p in enumerate(packets, 1):
    print(f"   {i}. {p.summary()}")
