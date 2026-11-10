# CSCE 313 — scapy packet practice

Eighteen short Python programs for the packet-manipulation lectures, using
[Scapy](https://scapy.net). They build, inspect, take apart and save network
packets so you can see exactly what goes on the wire.

Companion repositories: [`practice-1`](https://github.com/CSCE-313-FA26/practice-1)
(fork, wait, exec), [`ipc-practice`](https://github.com/CSCE-313-FA26/ipc-practice)
(pipes, dup2, FIFOs), [`signals-practice`](https://github.com/CSCE-313-FA26/signals-practice)
(handlers, masks, reaping) and [`threads-practice`](https://github.com/CSCE-313-FA26/threads-practice)
(mutexes, condition variables, semaphores).

```bash
git clone https://github.com/CSCE-313-FA26/scapy-practice.git
cd scapy-practice
make run          # runs every example that does not need root, in order
```

Scapy is already installed on the lab machines (`python3 -c "import scapy"`).
There is nothing to compile — these are Python scripts. Run any one on its own:

```bash
python3 build/layer_stack.py
```

## Root, and why almost nothing here needs it

**Putting a packet on a wire needs a raw socket, and a raw socket needs root.**
On a shared lab machine you do not have that, so `send()`, `sendp()`, `sr1()`
and live `sniff()` will fail with `Operation not permitted`. That is expected,
and it is not a bug in your code.

Everything you need in order to *build, inspect and manipulate* packets works
without root, because it never touches a wire. You craft packets in memory,
turn them into bytes, read them back, and save them to capture files. The two
programs in `live/` are the only ones that need root, and each prints the
offline way to get the same result.

```
build/       inspect/     dissect/      protocols/    pcap/        live/
no root      no root      no root       no root       no root      ROOT
```

## The programs

| File | What it shows |
| --- | --- |
| `build/ip_defaults.py` | one `IP()` packet and every default Scapy fills in |
| `build/layer_stack.py` | the `/` operator: `Ether()/IP()/TCP()/Raw()` |
| `build/set_fields.py` | setting fields two ways — same wire bytes |
| `inspect/summary_show.py` | `.summary()`, `repr()` and `.show()` side by side |
| `inspect/list_fields.py` | `ls(IP)`, `ls(TCP)` — every field, type and default |
| `inspect/hexdump_bytes.py` | `bytes(pkt)` and `hexdump(pkt)` — the packet as wire bytes |
| `dissect/layers.py` | `pkt[TCP]`, `TCP in pkt`, `.payload` — reaching inside |
| `dissect/reparse.py` | bytes → layers again: what a sniffer does to raw bytes |
| `dissect/checksums.py` | let Scapy compute `len`/`chksum`; recompute after a change |
| `protocols/tcp_syn.py` | a TCP SYN and the named flag bits (`S`, `SA`, `F`, …) |
| `protocols/dns_query.py` | a DNS question over UDP/53, read back out |
| `protocols/arp_request.py` | an ARP "who-has" broadcast |
| `pcap/write_pcap.py` | craft packets and `wrpcap()` them to `sample.pcap` |
| `pcap/read_pcap.py` | `rdpcap()` the capture and walk through it |
| `pcap/modify_pcap.py` | read a packet, change a field, write it back — offline |
| `pcap/filter_pcap.py` | pick packets out of a capture by what is inside them |
| `live/send.py` | `send()` / `sendp()` — **needs root**; offline stand-in shown |
| `live/sniff.py` | `sniff()` live (**root**) **or** from a file (everyone) |

`make run` runs the sixteen no-root programs one after another. `make pcap`
regenerates the capture file; `make clean` removes caches and scratch output.

## The idea in one example

A packet is an object you can read and change, and it is also just bytes.
`build/layer_stack.py`:

```
summary(): Ether / IP / TCP ... :ftp_data > 192.0.2.1:http S / Raw

The layers, outermost first:
    Ether
    IP
    TCP
    Raw

Scapy set each layer's 'type'/'proto' field to match the next layer up:
   Ether.type = 0x800 (0x0800 = IPv4)
   IP.proto   = 6 (6 = TCP)
```

You build a packet by stacking layers with `/`, and Scapy fills in the glue —
the EtherType that says "IPv4 is next", the IP protocol number that says "TCP
is next", and later the lengths and checksums. You only set what you care about.

## Capture files are the offline workhorse

You cannot sniff a live wire without root, but you *can* read and write `.pcap`
capture files freely — the same format Wireshark and tcpdump use. So the way to
practise handling "captured" traffic is to read it from a file:

```bash
python3 pcap/write_pcap.py     # creates pcap/sample.pcap
python3 pcap/read_pcap.py      # reads it back
python3 pcap/filter_pcap.py    # finds the SYNs and DNS questions in it
python3 pcap/modify_pcap.py    # changes a TTL and writes the packet out again
```

`sample.pcap` is committed, so the reading programs work the moment you clone.
`sniff()` reads a file too — `live/sniff.py` runs its callback over
`sample.pcap` with no privilege at all, and the callback is written exactly the
way it would be for a live interface.

## If you want to send or sniff for real

On your **own** machine, where you have `sudo`:

```bash
sudo python3 live/send.py
sudo python3 -c "from scapy.all import sniff; sniff(prn=lambda p: p.summary(), count=5)"
```

Never run these against a network that is not yours. On the lab machines they
will simply report that they cannot open a raw socket, which is correct.
