#!/usr/bin/env python3
"""An ARP 'who-has' request: find the MAC address for an IP on the LAN.

ARP maps an IP address to a hardware (MAC) address. A request is broadcast
to ff:ff:ff:ff:ff:ff -- 'who has 10.9.0.5? tell me'. This is the packet
shape behind every 'arp' command; we only build it here.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, ARP

who_has = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst="10.9.0.5")

who_has.show()
print("Ethernet dst :", who_has[Ether].dst, "(broadcast -- every host on the LAN sees it)")
print("ARP op       :", who_has[ARP].op, "(1 = who-has/request, 2 = is-at/reply)")
print("Asking for   :", who_has[ARP].pdst)
