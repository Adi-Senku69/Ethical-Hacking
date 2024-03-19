#!/usr/bin/env python

# iptables -I FORWARD -j NFQUEUE --queue-num [queue num]
import netfilterqueue as net
import scapy.all as scapy
import re

def process_packet(packet):
    # Converting packet into scapy packet
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[scapy.TCP].dport == 80:
                if ".exe" in str(scapy_packet[scapy.Raw].load):
                    print("[+] exe Request")
                    print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                print("HTTP Response")


    packet.accept() # Accepts all packets

queue = net.NetfilterQueue()
queue.bind(0, process_packet) # queue number and callback
queue.run()