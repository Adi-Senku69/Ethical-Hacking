#!/usr/bin/env python

# iptables -I FORWARD -j NFQUEUE --queue-num [queue num]
import netfilterqueue as net
import scapy.all as scapy
import re

ack_list = []

def process_packet(packet):
    # Converting packet into scapy packet
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[scapy.TCP].dport == 80:
                if ".exe" in str(scapy_packet[scapy.Raw].load):
                    print("[+] exe Request")
                    ack_list.append(scapy_packet[scapy.TCP].ack)
                    print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy_packet].seq in ack_list:
                    print(f"Response to the particular packet with sequence {scapy_packet[scapy.TCP].seq}")
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("HTTP Response")


    packet.accept() # Accepts all packets

queue = net.NetfilterQueue()
queue.bind(0, process_packet) # queue number and callback
queue.run()