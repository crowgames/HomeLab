import re

from scapy.layers.inet import TCP
from scapy.utils import rdpcap

packets = rdpcap('/full_capture.pcap')

# Let's iterate through every packet
for pkt in packets:
    # We're only interested packets with a DNS Round Robin layer
    if pkt.haslayer(TCP):
        # If the an(swer) is a DNSRR, print the name it replied with.
        if pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
            #.decode("utf-8")
            print(str(pkt.payload, 'utf-8'))
            #print(re.sub(re.compile('\W+'),'',str(pkt.payload)))