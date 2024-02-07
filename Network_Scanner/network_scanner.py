#!/usr/bin/env python

from scapy.all import *
import argparse


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

def scan(ip):
    scapy.arping(ip)

def get_aguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="IP_address", help="Input the destination IP address or subnet mask")
    options = parser.parse_args()
    if not options.IP_address:
        parser.error("Please specify a target IP address or subnet mask")
    return options


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
    print("IP \t\t\t\t MAC Address")
    print("------------------------------------------------------------------")
    for clients in clients_list:
        print(f"{clients['ip']}\t\t\t{clients['mac']}")




options = get_aguments()
test = scan_manual(options.IP_address)
print_addresses(test)
