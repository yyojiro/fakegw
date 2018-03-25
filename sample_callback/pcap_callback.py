# -*- coding: utf-8 -*-
from scapy.utils import PcapWriter

# write packet data to this file
PCAP_FILE = "test.pcap"
pcap_wirter = PcapWriter(PCAP_FILE, append=True, sync=True)

def fakegw_callback(packet):
    pcap_wirter.write(packet)
