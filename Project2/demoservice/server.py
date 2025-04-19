from socket import socket, AF_INET, SOCK_STREAM
import threading


class TCPServer:
    def __init__(self, port):
        """
        Args:
            port (int) - the TCP server port
        """

        self.port = port

    def start(self):
        """Listen indefinitely for TCP connections from multiple clients."""

        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind(('0.0.0.0', self.port))
        sock.listen(10)  # the TCP queue size
        print("Started service...")

        while True:
            # we need to accept a connection from client first. this gives
            # us a client socket that can be used for birectional messages.
            (client_sock, client_addr) = sock.accept()

            # receive
            message = client_sock.recv(1024)
            print(f'{client_addr} -> {message.decode()}')

            # send
            client_sock.send(b'Hello Client.')


if __name__ == '__main__':
    server = TCPServer(9999)
    threading.Thread(target=server.start, args=()).start()
