#!/usr/bin/env python

from scapy.all import *
import re
from pprint import pprint


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

def scan(ip):
    scapy.arping(ip)


def scan_manual(ip: str) -> list:
    clients_list = []
    arp_request = ARP(pdst=ip)
    # arp_request.pdst = ip
    # scapy.ls(scapy.ARP()) # Lists all the fields which can be set
    broadcast = Ether(dst=BROADCAST_MAC)
    arp_request_broadcast = broadcast/arp_request
    answered_response_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    # print(answered_response_list.summary())
    # answered_response_list.summary(lambda s,r: r.sprintf("%Ether.src% %Ether.psrc%"))
    for responses in answered_response_list:
        responses_dict = {}
        responses_dict["mac"] = responses[1].hwsrc
        responses_dict["ip"] = responses[1].psrc
        clients_list.append(responses_dict)

    return clients_list

def print_addresses(clients_list: list):
    print("\t\tIP \t\t\t\t\t MAC Address")
    print("-------------------------------------------")
    for clients in clients_list:
        print(f"{clients['ip']}\t\t\t{clients['mac']}")





test = scan_manual("192.168.146.1/24")
print_addresses(test)
