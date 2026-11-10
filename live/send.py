#!/usr/bin/env python3
"""Continuously put a VARIETY of packets on the wire, until you press a key.

Run this in one terminal and live/sniff.py in another: sniff.py captures and
dissects everything this program sends, as it is sent.

Putting real frames on a real interface needs root (see the README), so this
demo transmits over a no-root loopback "wire" instead -- live/wire.py explains
exactly what that stand-in is and how it differs from a real send. The packets
themselves are built the ordinary way.

Press any key (or Ctrl-C) to stop.
"""
import os
import sys
import time
import select
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, ICMP, TCP, UDP, DNS, DNSQR, ARP, Raw

import wire   # live/wire.py -- the no-root stand-in interface

# Pinned source addresses, so the output is the same on every machine and no
# real address of yours ever leaves the box. Locally-administered MAC (the
# 02: prefix) and an RFC 1918 / lab-style source IP.
CLIENT_MAC = "02:00:00:00:00:06"
SRC_IP     = "10.9.0.6"
BROADCAST  = "ff:ff:ff:ff:ff:ff"

INTERVAL = 1.0   # seconds between packets


def eth(payload):
    """Frame a packet in Ethernet with our fixed source MAC."""
    return Ether(src=CLIENT_MAC, dst="02:00:00:00:00:05") / payload


# A rotation of DIFFERENT packets, so each cycle shows something new. Everything
# is Ether-framed so the sniffer dissects it uniformly (same lesson as the pcap
# examples: build a capture with one consistent framing).
def build_rotation():
    return [
        eth(IP(src=SRC_IP, dst="10.9.0.5") / ICMP()),
        eth(IP(src=SRC_IP, dst="93.184.216.34") / TCP(dport=80,  flags="S")),
        eth(IP(src=SRC_IP, dst="93.184.216.34") / TCP(dport=443, flags="S")),
        eth(IP(src=SRC_IP, dst="8.8.8.8") / UDP(dport=53)
            / DNS(rd=1, qd=DNSQR(qname="tamu.edu"))),
        eth(IP(src=SRC_IP, dst="10.9.0.7") / UDP(sport=40000, dport=9999)
            / Raw(load=b"hello from CSCE 313")),
        Ether(src=CLIENT_MAC, dst=BROADCAST)
            / ARP(op=1, hwsrc=CLIENT_MAC, psrc=SRC_IP, pdst="10.9.0.1"),
    ]


def key_pressed(interactive):
    """True if a key is waiting on stdin. Doubles as our inter-packet wait:
    it blocks up to INTERVAL seconds, returning early the instant a key lands."""
    r, _, _ = select.select([sys.stdin], [], [], INTERVAL)
    if not r:
        return False
    if interactive:
        os.read(sys.stdin.fileno(), 1)   # consume the one key
    return True


def main():
    sock = wire.UDPWire()
    rotation = build_rotation()
    interactive = sys.stdin.isatty()

    print(f"Sending a packet every {INTERVAL:g}s over the {wire.HOST}:{wire.PORT} "
          "loopback wire.")
    print("Start live/sniff.py in another terminal to watch them arrive.")
    if interactive:
        print("Press any key (or Ctrl-C) to stop.\n")
    else:
        print("(stdin is not a terminal -- stop with Ctrl-C.)\n")

    # Put the terminal in cbreak mode so a single key stops us, no Enter needed.
    old = None
    if interactive:
        import termios, tty
        old = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())

    n = 0
    try:
        while True:
            pkt = rotation[n % len(rotation)]
            sock.send(pkt)
            n += 1
            print(f"  [{n:3d}] sent  {pkt.summary()}")
            if interactive:
                if key_pressed(True):
                    break
            else:
                time.sleep(INTERVAL)
    except KeyboardInterrupt:
        pass
    finally:
        if old is not None:
            import termios
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        sock.close()

    print(f"\nStopped. Sent {n} packet(s).")


if __name__ == "__main__":
    main()
