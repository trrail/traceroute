import socket

from icmp import IcmpPacket
from whois import WhoisTrace, Whois_Data

DATA_TO_RECV = 1024
PORT = 80


class Traceroute:
    def __init__(self, host: str, max_ttl: int):
        self._host = socket.gethostbyname(host)
        self._max_ttl = max_ttl

    def make_trace(self):
        ttl = 1
        while ttl <= self._max_ttl:
            send_sock, recv_sock = self.create_socks(ttl)
            icmp_pack = IcmpPacket(8, 0)
            send_sock.sendto(bytes(icmp_pack), (self._host, PORT))
            try:
                data, address = recv_sock.recvfrom(DATA_TO_RECV)
            except socket.timeout:
                yield 'server_timeout\n'
                ttl += 1
                continue
            whois_data = WhoisTrace().get_whois_data(address[0])
            yield Whois_Data(address[0], whois_data)
            recv_icmp = IcmpPacket.from_bytes(data[20:])
            if recv_icmp.type == recv_icmp.code == 0:
                send_sock.close()
                recv_sock.close()
                break
            ttl += 1
            send_sock.close()
            recv_sock.close()

    def create_socks(self, ttl) -> tuple:
        send_sock = socket.socket(socket.AF_INET, socket.IPPROTO_ICMP, socket.SOCK_DGRAM)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_sock = socket.socket(socket.AF_INET,
                                  socket.IPPROTO_ICMP)
        recv_sock.settimeout(4)
        return send_sock, recv_sock
