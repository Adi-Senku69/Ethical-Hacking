#!/usr/bin/env python

import scapy.all as scapy


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

def scan(ip):
    scapy.arping(ip)


def scan_manual(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.pdst = ip
    # scapy.ls(scapy.ARP()) # Lists all the fields which can be set
    broadcast = scapy.Ether(dst=BROADCAST_MAC)
    arp_request_broadcast = broadcast/arp_request
    print(arp_request_broadcast.show())

scan_manual("192.146.168.1/24")
