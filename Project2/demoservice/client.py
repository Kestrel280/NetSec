from socket import socket, AF_INET, SOCK_STREAM


class TCPClient:
    def __init__(self, server, port):
        """
        Args:
            server (str) - the TCP server address
            port (int) - the TCP server port
        """

        self.server = server
        self.port = port

    def send(self, message):
        """Send a message to the server over a TCP connection.

        Args:
            message (str) - the message to send
        """

        # unlike UDP, we need to establish a connection with the server.
        # using the connection, we can then send and receive messages.
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.server, self.port))

        # send
        sock.send(message)

        # receive
        received = sock.recv(1024)
        print(f'server -> {received.decode()}')

        # both client or server can close connection
        sock.close()


if __name__ == '__main__':
    client = TCPClient('127.0.0.1', 9999)
    # //add encrypt
    client.send(b'Hello Server.')
