#!/usr/bin/env python

import scapy.all as scapy


BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

def scan(ip):
    scapy.arping(ip)


def scan_manual(ip):
    arp_request = scapy.ARP(pdst=ip, hwdst=BROADCAST_MAC)
    # arp_request.pdst = ip
    print(arp_request.summary())
    # scapy.ls(scapy.ARP()) # Lists all the fields which can be set


scan_manual("192.146.168.1/24")
