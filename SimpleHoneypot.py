import asyncore
import logging
import urllib.parse
import socket


class Log4jServer(asyncore.dispatcher):
    def __init__(self, address):
        self.server_port = address[1]
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(address)
        self.address = self.socket.getsockname()
        self.listen(1024)
        return

    def handle_accept(self):
        sock, addr = self.accept()
        handler = Log4jHandler(sock, addr, self.server_port)

    def handle_close(self):
        self.close()
        return


class Log4jHandler(asyncore.dispatcher_with_send):
    def __init__(self, sock, addr, server_port):
        self.server_port = server_port
        self.client = addr
        self.data = b''
        self.out_buffer = b''
        self.logger = logging.getLogger('Possible CVE-2021-44228 Attempt: %s:%s -> port %s' %
                                        (self.client[0], self.client[1], self.server_port))
        asyncore.dispatcher.__init__(self, sock=sock)
        return

    def handle_read(self):
        self.data += self.recv(4096)
        self.send(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nServer: %s\r\n\r\n%s' %
                  (len(config['server_msg']), config['server_name'], config['server_msg']))
        self.handle_close()
        self.data = self.data.replace(b'\r', b'')
        for line in self.data.split(b'\n'):
            line = urllib.parse.unquote(line.decode('utf-8'))
            if line.find('${') != -1:
                self.logger.info(line)

    def handle_close(self):
        self.close()


if __name__ == '__main__':
    config = {
        'server_name': b'BudgetMemes',
        'server_msg': b'API Error',
        'server_ports': [80, 8080, 1337]
    }

    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(name)s - %(message)s', handlers=[
        logging.FileHandler("cve-2021-44228.log"),
        logging.StreamHandler()
    ])

    for port in config['server_ports']:
        server = Log4jServer(('0.0.0.0', port))

    asyncore.loop()
