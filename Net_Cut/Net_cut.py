#!/usr/bin/env python
# iptables -I FORWARD -j NFQUEUE --queue-num [queue number]
import netfilterqueue as net

def process_packet(packet):
    print(packet)
    packet.drop() # All the packets will be dropped

queue = net.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()