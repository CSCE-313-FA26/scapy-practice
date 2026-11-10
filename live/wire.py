#!/usr/bin/env python3
"""A stand-in 'wire' that needs no root, so send + sniff can run in the lab.

A real sniffer reads frames off a network interface, and putting frames onto
one needs a raw socket -- which needs root (see the README). On a shared lab
machine you do not have that.

So these two demos (send.py and sniff.py) talk over an ordinary UDP socket on
loopback instead of a real interface. send.py puts the BYTES of each Scapy
packet into a datagram; sniff.py reads the datagram and hands the bytes back
to Scapy to dissect. Nothing here needs privilege, yet:

  * the packets are built exactly as for a real send,
  * sniff.py calls the real scapy sniff() with a real prn callback, and
  * each captured frame is dissected exactly as off a real wire.

The ONLY difference from the real thing is the transport underneath. On a
machine where you have root you would drop this file and instead use, at
layer 2:

    sendp(pkt, iface="eth0")                      # put a frame on eth0
    sniff(iface="eth0", prn=cb, store=False)      # read frames off eth0

Both of those open a raw socket, so both need root. This UDP stand-in does
not, which is the whole point.
"""
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, SuperSocket

# The loopback "wire": a fixed address every sender and sniffer agrees on.
HOST = "127.0.0.1"
PORT = 31313            # arbitrary, just has to match on both ends


class UDPWire(SuperSocket):
    """A non-raw SuperSocket: a plain UDP datagram socket on loopback.

    scapy's sniff() can read from any object that looks like a SuperSocket --
    it selects on fileno() and calls recv(). We make recv() dissect each
    datagram as an Ethernet frame, so to sniff() this is indistinguishable
    from a real L2 interface.
    """
    desc = "loopback UDP stand-in for a real interface (no root needed)"

    def __init__(self, listen=False):
        self.ins = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.outs = self.ins
        if listen:
            # A sniffer binds the port so datagrams are delivered to it.
            self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.ins.bind((HOST, PORT))

    def recv(self, x=0xFFFF):
        data, _ = self.ins.recvfrom(x)
        if not data:
            return None
        # Hand the raw bytes back to Scapy -- the same dissection a real
        # sniffer does. We framed everything with Ether() on the way out.
        return Ether(data)

    def send(self, pkt):
        return self.outs.sendto(bytes(pkt), (HOST, PORT))
