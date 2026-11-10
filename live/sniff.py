#!/usr/bin/env python3
"""Continuously sniff and dissect every packet live/send.py is sending.

Run this in one terminal and live/send.py in another. This program calls the
real scapy sniff() with a real prn callback -- exactly what you would write for
a live interface -- but reads from a no-root loopback "wire" (see live/wire.py)
so it runs in the lab without privilege.

On a machine where you have root, the only change for a REAL interface is the
source you sniff from:

    sniff(iface="eth0", prn=show_pkt, store=False)   # needs root

Stop with Ctrl-C.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR

import wire   # live/wire.py -- the no-root stand-in interface

count = 0


def describe(pkt):
    """A short, protocol-aware line -- what a sniffer is really for."""
    if ARP in pkt:
        a = pkt[ARP]
        return f"ARP   who-has {a.pdst}?  tell {a.psrc}"
    if IP not in pkt:
        return pkt.summary()
    ip = pkt[IP]
    if ICMP in pkt:
        return f"ICMP  {ip.src} -> {ip.dst}   echo-request"
    if TCP in pkt:
        t = pkt[TCP]
        return f"TCP   {ip.src} -> {ip.dst}:{t.dport}   flags={t.flags}"
    if UDP in pkt:
        if DNS in pkt and pkt[DNS].qdcount and pkt[DNS].qd is not None:
            q = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
            if q:
                return f"DNS   {ip.src} -> {ip.dst}   query {q}"
        return f"UDP   {ip.src} -> {ip.dst}:{pkt[UDP].dport}   {len(pkt[UDP].payload)} bytes"
    return f"IP    {ip.src} -> {ip.dst}   {ip.proto}"


def show_pkt(pkt):
    global count
    count += 1
    print(f"  [{count:3d}] {describe(pkt)}")


def main():
    sock = wire.UDPWire(listen=True)
    print(f"Sniffing the {wire.HOST}:{wire.PORT} loopback wire (no root needed).")
    print("Start live/send.py in another terminal.  Ctrl-C to stop.\n")
    try:
        # The real sniff() loop: one prn call per captured packet, forever.
        sniff(opened_socket=sock, prn=show_pkt, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    print(f"\nStopped. Captured {count} packet(s).")


if __name__ == "__main__":
    main()
