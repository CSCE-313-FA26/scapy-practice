#!/usr/bin/env python3
"""Put a packet on the wire.  REQUIRES ROOT.

  send(pkt)    sends at layer 3 (IP) -- the OS picks the interface and MAC
  sendp(pkt)   sends at layer 2 (Ether) -- you control the whole frame

Opening a raw socket needs privilege, so on a shared lab machine this will
fail with 'Operation not permitted'. That is expected. Everything you need
to PRACTISE building and inspecting packets is in the other folders and runs
without root; sending is the one step that does not.

Offline stand-in: write the same packet to a file with wrpcap() (see
../pcap/write_pcap.py) and read it back -- the packet is identical, it just
never touches a wire.
"""
import logging, os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, ICMP, send, conf
conf.verb = 0

pkt = IP(dst="127.0.0.1") / ICMP()
print("Built:", pkt.summary())

if os.geteuid() != 0:
    print("\nNot running as root -- send() needs a raw socket, which needs root.")
    print("On your own machine you could run:  sudo python3 live/send.py")
    print("Offline instead:  python3 pcap/write_pcap.py   (saves packets to a file)")
else:
    send(pkt)
    print("Sent one ICMP echo request to 127.0.0.1.")
