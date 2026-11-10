#!/usr/bin/env python3
"""ls() lists every field of a protocol: its name, type and default.

This is the reference you reach for when you forget what a field is called
or what it defaults to. Works on a class (IP) or on an instance.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ls, IP, TCP

print("========== IP fields ==========")
ls(IP)
print("\n========== TCP fields ==========")
ls(TCP)
