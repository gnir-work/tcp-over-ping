from scapy.all import *
import socket


def send_ping_packet(payload: str, src=socket.gethostname(), dst=socket.gethostname()) -> None:
    response = sr1(IP(dst=dst, src=src) / ICMP() / Raw(load=payload))
    print(response[Raw].load.decode('utf-8'))


if __name__ == "__main__":
    conf.L3socket = L3RawSocket
    send_ping_packet("test")
