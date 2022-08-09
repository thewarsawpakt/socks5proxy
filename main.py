import socket
import threading
import ipaddress
import select
import configparser


USERNAME_PASSWORD_AUTHENTICATION = int.to_bytes(5, 1, "little") + int.to_bytes(2, 1, "little")
NO_AUTHENTICATION = int.to_bytes(5, 1, "little") + int.to_bytes(0, 1, "little")


class SOCKS5ClientConnection:
    def __init__(self, configuration, _socket, address):
        self.client_socket = _socket
        self._configuration = configuration
        self._address = address

    def run(self) -> threading.Thread:
        self.thread = threading.Thread(target=self._run)
        self.thread.start()

    def _run(self):
        self.get_connection_methods()
        if self._configuration.get("config", "AUTHENTICATION") == "username_password":
            self.client_socket.send(USERNAME_PASSWORD_AUTHENTICATION)
        else:
            self.client_socket.send(NO_AUTHENTICATION)
        if self._configuration.get("config", "authentication"):
            self.username_password_auth()
        self.request()

    def username_password_auth(self):
        self.client_socket.recv(1)
        ulen = int.from_bytes(self.client_socket.recv(1), "little")
        uname = self.client_socket.recv(ulen).decode()
        plen = int.from_bytes(self.client_socket.recv(1), "little")
        passwd = self.client_socket.recv(plen).decode()
        if uname == self._configuration.username and passwd == self._configuration.password:
            self.client_socket.send(int(1).to_bytes(1, "little") + int(0).to_bytes(1, "little"))
        else:
            self.client_socket.send(int(1).to_bytes(1, "little") + int(1).to_bytes(1, "little"))
            self.cleanup()

    def get_connection_methods(self):
        ver = int.from_bytes(self.client_socket.recv(1), "little")
        nmethods = int.from_bytes(self.client_socket.recv(1), "little")
        methods = []
        for i in range(0, nmethods):
            methods.append(int.from_bytes(self.client_socket.recv(1), "little"))

    def get_client_connection_request(self):
        self.client_socket.recv(1)
        cmd = int.from_bytes(self.client_socket.recv(1), "little")
        self.client_socket.recv(1)
        _type = int.from_bytes(self.client_socket.recv(1), "little")
        match _type:
            case 1:
                # IPV4
                address = ipaddress.IPv4Address(self.client_socket.recv(4))
            case 3:
                # Domain name
                length = int.from_bytes(self.client_socket.recv(1))
                address = ipaddress.ip_address(socket.gethostbyname(self.client_socket.recv(length).decode()))
            case 4:
                # IPV6
                address = ipaddress.IPv6Address(self.client_socket.recv(16))
            case _:
                return None
        port = socket.htons(int.from_bytes(self.client_socket.recv(2), "little"))
        return cmd, _type, address, port

    def _create_tcp_proxy_stream(self, _type, address, port):
        address_family = socket.AF_INET if _type == 1 else socket.AF_INET6
        self.client_socket.send(
            int(5).to_bytes(1, "little") +
            int(0).to_bytes(1, "little") +
            b"\x00" + int(_type).to_bytes(1, "little") +
            socket.inet_pton(address_family, str(address)) +
            int(port).to_bytes(2, "big")
        )
        self.remote_socket = socket.socket(address_family, socket.SOCK_STREAM)
        self.remote_socket.connect((str(address), port))
        self.remote_socket.setblocking(False)
        self.client_socket.setblocking(False)

        errors = 0
        while errors < 10:
            client_send_buffer = bytes()
            remote_send_buffer = bytes()
            readable, writeable, _ = select.select(
                [self.remote_socket, self.client_socket],
                [self.remote_socket, self.client_socket],
                []
            )
            try:
                for event in readable:  # File Descriptors that we are able to read from
                    data = event.recv(512)
                    if event is self.client_socket:
                        remote_send_buffer = data  # If there is data in the client socket, we put that in the buffer to send to the remote socket
                    else:
                        client_send_buffer = data  # If there is data in the remote socket, we put that in the buffer to send to the client socket
                for event in writeable:
                    if event is self.client_socket:
                        # If the client is ready to be written to, we send it the remote socket's buffer
                        self.client_socket.send(client_send_buffer)
                    elif event is self.remote_socket:
                        # If the remote is ready to be written to, we send it the client socket's buffer
                        self.remote_socket.send(remote_send_buffer)
            except (BrokenPipeError, ConnectionResetError, ValueError) as e:
                if isinstance(e, ConnectionResetError):
                    errors += 1
                if isinstance(e, ValueError): # This is probably a select error which means something has gone horribly wrong
                    errors += 10
        return

    def request(self):
        cmd, _type, address, port = self.get_client_connection_request()
        match cmd:
            case 1:
                # TCP/IP Stream
                self._create_tcp_proxy_stream(_type, address, port)
            case 2:
                # Establish TCP/IP port binding
                raise NotImplementedError
            case 3:
                # Associate a UDP port
                raise NotImplementedError

    def cleanup(self):
        self.client_socket.close()
        if hasattr(self, "remote_socket"):
            self.remote_socket.close()

        self.thread.join()


def main(config):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    addr = (config.get("config", "host"), int(config.get("config", "port")))
    s.bind(addr)
    print(f"Listening on {addr[0]}:{addr[1]}...")
    s.listen(10)
    workers = []
    try:
        while True:
            sock, addr = s.accept()
            client = SOCKS5ClientConnection(config, sock, addr)
            client.run()
            workers.append(client)
    except KeyboardInterrupt:
        print("Keyboard interrupt received, closing threads and exiting.")
        for client in workers:
            client.cleanup()


if __name__ == "__main__":
    r = configparser.ConfigParser()
    r.read("example.cfg")
    main(r)