from scapy.all import Packet, sniff
from scapy.all import *


def pkt_callback(packet: Packet) -> None:
    print(packet[Raw].load)


def start_sniffing() -> None:
    sniff(iface="enp3s0", prn=pkt_callback, filter="icmp[icmptype] == icmp-echo", store=0)


if __name__ == "__main__":
    print("starting to sniff")
    start_sniffing()
