import os
import socket
import ssl
import sys
import threading

PORT = 10179

def client1():
    print("C1: Starting")
    
    ctxt = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)                  # Initialize SSL context as "server" (because we're accepting the connection, not because we're actually a "server")
    ctxt.verify_mode = ssl.CERT_REQUIRED                            # Require the peer to provide its certificate, we will verify against the CA it provides
    ctxt.load_verify_locations('ca.crt')
    ctxt.load_cert_chain('c1.crt', 'c1.key')                        # Set our SSL context to use our certificate

    lstnsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Standard socket stuff: create a listener
    lstnsock.bind(('localhost', PORT))
    lstnsock.listen(1)

    print("C1: Listening for connection from C2")
    slstnsock = ctxt.wrap_socket(lstnsock, server_side = True)      # Wrap the listener socket using our SSL context
    ssock, addr = slstnsock.accept()                                 # Accept connection *and verify its identity*
    print(f"C1: Connected to C2 and verified its identity! For encryption, we are communicating using: {ssock.cipher()}")
    print(f"C1: getpeercert gives: {ssock.getpeercert()}")

    ssock.send("Hello from client 1, this message was encrypted using TLS!".encode('utf-8'))
    msg = ssock.recv(1024).decode('utf-8')
    print(f"C1: Received msg from client 2: {msg}")

def client2():
    print("C2: Starting")

    ctxt = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)                  # Initialize SSL context as "server" (because we're accepting the connection, not because we're actually a "server")
    ctxt.load_verify_locations('ca.crt')                            # Load the CA certificate: this is the CA we will use to verify that the target is who it says it is
    ctxt.load_cert_chain('c2.crt', 'c2.key')                        # Load our own certificate into our context: when we connect using the wrapped socket, we'll send our certificate as well

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # Create socket
    ssock = ctxt.wrap_socket(sock, server_hostname = 'Client 1')    # Wrap the socket using SSL module
    ssock.connect(('localhost', PORT))                              # Connect to target and verify its identity
    print(f"C2: Connected to C1 and verified its identity! For encryption, we are communicating using: {ssock.cipher()}")
    print(f"C2: getpeercert gives: {ssock.getpeercert()}")

    msg = ssock.recv(1024).decode('utf-8')
    print(f"C2: Received msg from client 1: {msg}")
    ssock.send("Hi client 1, this is client 2. This message was encrypted using TLS!".encode('utf-8'))


if __name__ == '__main__':
    os.environ["REQUESTS_CA_BUNDLE"] = 'ca.crt'
    os.environ["SSL_CERT_FILE"] = 'ca.crt'

    c1thread = threading.Thread(target = client1)
    c2thread = threading.Thread(target = client2)
    
    c1thread.start()
    c2thread.start()

    print("Main waiting on c1 + c2 to finish")
    c1thread.join()
    c2thread.join()
    print("Main all done")
