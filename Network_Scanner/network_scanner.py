#!/usr/bin/env python

from scapy.all import *
import re


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

def scan(ip):
    scapy.arping(ip)


def scan_manual(ip):
    arp_request = ARP(pdst=ip)
    # arp_request.pdst = ip
    # scapy.ls(scapy.ARP()) # Lists all the fields which can be set
    broadcast = Ether(dst=BROADCAST_MAC)
    arp_request_broadcast = broadcast/arp_request
    answered_response_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    # print(answered_response_list.summary())
    # answered_response_list.summary(lambda s,r: r.sprintf("%Ether.src% %Ether.psrc%"))
    print("\t\tIP \t\t\t\t\t MAC Address")
    print("-------------------------------------------")
    for responses in answered_response_list:
        print(f"{responses[1].psrc}\t\t\t{responses[1].hwsrc}")





scan_manual("192.168.146.1/24")
