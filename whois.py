import socket


class Whois_Data:
    def __init__(self, address: str, whois_data: dict):
        self.address = address
        self.name = ''
        try:
            self.name = socket.gethostbyaddr(address)[0]
        except socket.herror:
            pass
        self.country = ''
        self.auto_sys = ''
        if 'country' in whois_data and 'EU' not in whois_data["country"]:
            self.country = whois_data["country"]
        if 'origin' in whois_data:
            self.auto_sys = whois_data['origin']
        if 'originas' in whois_data:
            self.auto_sys = whois_data['originas']

    def _make_result_str(self):
        result = f'{self.address}\n'
        if self.name and not self.auto_sys and not self.country:
            result += f'{self.name}\n'
        elif self.name:
            result += f'{self.name}, '
        if self.auto_sys and not self.country:
            result += f'{self.auto_sys}\n'
        elif self.auto_sys:
            result += f'{self.auto_sys}, '
        if self.country:
            result += f'{self.country}\n'
        return result

    def __str__(self):
        return self._make_result_str()


DATA_TO_RECV = 1024


class WhoisTrace:
    def create_whois_sock(self, data):
        refer_ind = data.index('refer')
        first_data = data[refer_ind:].split('\n')[0].replace(' ', '').split(':')
        server_name = first_data[1]
        whois_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return whois_sock, server_name

    def create_sock(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        return sock

    def get_whois_data(self, address: str):
        sock = self.create_sock()
        sock.connect((socket.gethostbyname('whois.iana.org'), 43))
        sock.send((address + '\r\n').encode('utf-8'))
        result = {}
        try:
            first_data = sock.recv(1024).decode()
            if 'refer' in first_data:
                whois_sock, server_name = self.create_whois_sock(first_data)
                whois_sock.connect((server_name, 43))
                whois_sock.send((address + '\r\n').encode('utf-8'))
                data = self.get_data(whois_sock)
                return self.parse_result(data, result)
        except socket.timeout:
            pass
        finally:
            sock.close()
            return result

    def get_data(self, whois_sock):
        data = b''
        current_part = whois_sock.recv(DATA_TO_RECV)
        while current_part != b'':
            data += current_part
            current_part = whois_sock.recv(DATA_TO_RECV)
        return data.decode().lower()

    def parse_result(self, data, result):
        for el in ['country', 'origin', 'originas']:
            if el in data:
                ind = data.index(el)
                record = data[ind:].split('\n')[0]
                record = record.replace(' ', '').split(':')
                result[record[0]] = record[1]
        return result

