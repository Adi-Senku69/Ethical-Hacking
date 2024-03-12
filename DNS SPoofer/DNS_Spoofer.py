#!/usr/bin/env python

# iptables -I FORWARD -j NFQUEUE --queue-num [queue num]

import netfilterqueue as net
import scapy.all as scapy

def process_packet(packet):
    # Converting packet into scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    print(packet.get_payload()) # Shows the contents inside the packet itself
    packet.accept() # Accepts all packets

queue = net.NetfilterQueue()
queue.bind(0, process_packet) # queue number and callback
queue.run()