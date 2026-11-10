# CSCE 313 - scapy packet-manipulation practice
#
# These are Python scripts; there is nothing to compile. The targets just run
# the examples. Everything under build/ inspect/ dissect/ protocols/ pcap/
# runs WITHOUT root and finishes on its own -- `make run` runs them in order.
#
# live/ holds the two continuous demos (send + sniff). They also run without
# root (over a loopback stand-in; see live/wire.py), but they run until you
# stop them, so they are NOT part of `make run`. Start each in its own
# terminal:  `make sniff` in one, `make send` in another.

PY = python3

# Every example that runs without root AND finishes on its own, in teaching order.
OFFLINE = \
  build/ip_defaults.py build/layer_stack.py build/set_fields.py \
  inspect/summary_show.py inspect/list_fields.py inspect/hexdump_bytes.py \
  dissect/layers.py dissect/reparse.py dissect/checksums.py \
  protocols/tcp_syn.py protocols/dns_query.py protocols/arp_request.py \
  pcap/write_pcap.py pcap/read_pcap.py pcap/modify_pcap.py pcap/filter_pcap.py

run: pcap/sample.pcap
	@for f in $(OFFLINE); do \
	  echo "========================================================"; \
	  echo "## $$f"; echo "========================================================"; \
	  $(PY) $$f || exit 1; echo; \
	done

# The two continuous demos. Run `make sniff` in one terminal and `make send`
# in another; the sniffer prints every packet the sender puts on the wire.
sniff:
	$(PY) live/sniff.py

send:
	$(PY) live/send.py

# (Re)create the capture the pcap/ examples read.
pcap/sample.pcap: pcap/write_pcap.py
	$(PY) pcap/write_pcap.py

pcap: pcap/sample.pcap

clean:
	rm -rf __pycache__ */__pycache__ pcap/modified.pcap

.PHONY: run sniff send pcap clean
