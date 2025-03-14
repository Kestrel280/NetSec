import sys
import argparse
import socket
import time
import signal
import random
import threading
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from shared import *

# Globals
running = True          # Flag used to manage running state
listener_thread = 0     # Thread which is listening for connections from peer clients
peer_threads = []       # Array of threads which are managing peer clients
listen_port = 0         # Port on which we are listening for connections from peer clients
server = 0              # Connection object to the server
my_name = ''            # This client's name (passed by --name argument)

# Require 2 arguments: --network and --name
parser = argparse.ArgumentParser()
parser.add_argument("--network", help="Server IP to connect to.", type=str, metavar="{Server IP}", required=True)
parser.add_argument("--name", help="Name to assign to this client.", type=str, metavar="{Client name}", required=True)

# Function to shut down the client -- can be called manually, or by signal interrupt
def crash_handler(*args):
    global running
    print(f"(CLIENT) Client {my_name} received shutdown signal, shutting down...")
    running = False

def listen_for_peers(listen_socket):
    '''
    Function which runs in its own thread and constantly listens for connections from peer clients.
    When a connection request is received, this thread simply dispatches a new thread running handle_peer(),
        which handles all of the connection-establishing protocols and all further communication.
    '''
    while running:
        try:
            peer_socket, peer_address = listen_socket.accept()
            peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            thread = threading.Thread(target = handle_peer, args = (peer_socket, peer_address, 'UNKNOWN_CLIENT', False))
            thread.start()
            peer_threads.append(thread)
        except TimeoutError:
            pass
        except Exception as e:
            print("(CLIENT) Error accepting new peer")
            print(e)

    listen_socket.close()
    print(f"(CLIENT) Client {my_name} no longer accepting new connections...")

def handle_peer(peer_socket, peer_address, peer_name, establish):
    '''
    Function which runs in its own thread and handles all communications with a single peer.
    Threads with this function can be spawned in two ways, depending if we're the one initiating the connection or not:
        1. We requested a peer's details from the server (in the main thread) (establish = True)
        2. Our own listener socket accepted a connection (in the listener_thread) (establish = False) 
    '''

    # Initialize private key decryption object
    peer_priv_crypter = PKCS1_OAEP.new(my_rsa_priv)

    # --- We are initiating the connection-establish protocol ---
    if establish: 
        # Get the peer's public key from the server (Getting it from the peer directly would enable an easier MITM attack)
        server.send(f"GET_PUBLIC_KEY {peer_name}")                              # 0.1 Send request for peer public key
        peer_pub_key = RSA.importKey(server.recv())                             # 0.2 Receive peer public key

        # Send our name to the peer and wait for OK
        peer_socket.send(f"{my_name}".encode('utf-8'))                          # 1.1 Send my name
        if (peer_socket.recv(1024).decode('utf-8') != "OK"):                    # 2 Receive OK to generate sym key
            crash_handler()

        # Generate a symetric key to use for this peer, and an encryption object to use it with
        # Generate an RSA encrypter object using their public key
        # Encrypt the symetric key using the peer's public key and send it, wait for OK
        peer_sym_key = os.urandom(16)
        peer_sym_encrypter = AES.new(peer_sym_key, AES.MODE_GCM)
        peer_pub_crypter = PKCS1_OAEP.new(peer_pub_key)
        peer_aes_key_enc = peer_pub_crypter.encrypt(peer_sym_key)
        peer_socket.send(peer_aes_key_enc)                                      # 3 Send encrypted sym key

        # Receive their encrypted nonce, decrypt it, create our decrypter, send our encrypter nonce
        _peer_nonce_enc = peer_socket.recv(1024)                                # 4 Receive their encrypter nonce
        peer_nonce = peer_priv_crypter.decrypt(_peer_nonce_enc)
        peer_sym_decrypter = AES.new(peer_sym_key, AES.MODE_GCM, nonce = peer_nonce)

        _my_nonce_enc = peer_pub_crypter.encrypt(peer_sym_encrypter.nonce)
        peer_socket.send(_my_nonce_enc)                                         # 5 Send our encrypter nonce, encrypted using their public RSA key

        if (peer_socket.recv(1024).decode('utf-8') != "OK"):                    # 6 Receive OK
            crash_handler()
        
    # --- The peer is initiating the connection-establish protocol ---
    else:
        # Peer will first send its name
        peer_name = peer_socket.recv(1024).decode('utf-8')                      # 1.1 Receive peer's name

        # Ask the server for the public key of this peer
        # Generate an RSA encrypter object using their public key
        server.send(f"GET_PUBLIC_KEY {peer_name}")                              # 1.2 Ask server for peer's public key
        peer_pub_key = RSA.importKey(server.recv())                             # 1.3 Receive peer's public key
        peer_pub_crypter = PKCS1_OAEP.new(peer_pub_key)

        # Send OK
        peer_socket.send("OK".encode('utf-8'))                                  # 2 Send OK to generate sym key
        
        # Peer will generate and send symetric key, encrypted using my private key. Receive and decrypt
        peer_sym_key = peer_priv_crypter.decrypt(peer_socket.recv(1024))        # 3 Receive and decrypt sym key

        # Generate an encrypter object for our communication
        peer_sym_encrypter = AES.new(peer_sym_key, AES.MODE_GCM)
        peer_socket.send(peer_pub_crypter.encrypt(peer_sym_encrypter.nonce))    # 4 Send our encrypter nonce, encrypted using their public RSA key

        # Receive their encrypted nonce, decrypt it, create our decrypter, and send OK
        _peer_nonce_enc = peer_socket.recv(1024)                                # 5 Receive their encrypter nonce, encrypted using our public RSA key
        peer_nonce = peer_priv_crypter.decrypt(_peer_nonce_enc)
        peer_sym_decrypter = AES.new(peer_sym_key, AES.MODE_GCM, nonce = peer_nonce)
        peer_socket.send("OK".encode('utf-8'))                                  # 6 Send OK

    # Create a Connection object for this peer
    try:
        peer = Connection(peer_socket, peer_name, peer_address[0], peer_address[1], peer_pub_key, peer_pub_crypter, peer_priv_crypter, peer_sym_encrypter, peer_sym_decrypter)
    except NameError as e: # Connection already exists -- return this thread immediately
        print(f"(CLIENT) Client {my_name} failed to connect to peer {peer_name} -- already connected to a peer with this name")
        print(e)
        return
    except Exception as e:
        print(f"(CLIENT) Client {my_name} failed to connect to peer {peer_name} with error {e}")
        return

    print("(CLIENT) Client {} {} connection from peer {}".format(my_name, "established" if establish else "accepted", peer_name))

    # Begin message loop
    msg = peer.recv()
    while msg != '':
        print(f"(CLIENT) Client {my_name} received message {msg} from peer {peer.name}")
        if (msg == "PING"):
            peer.send("PONG")
        msg = peer.recv()
    peer.close()
    print(f"(CLIENT) Client {my_name} closed connection with peer {peer.name}")

if __name__ == '__main__':
    # Extract args from command line
    args = parser.parse_args()
    try:
        server_ip = args.network
        my_name = sanitize_name(args.name)
    except:
        print("Illegal arguments")
        exit()

    # Register emergency-termination function (to close socket in case of crash)
    signal.signal(signal.SIGINT, crash_handler)
    signal.signal(signal.SIGTERM, crash_handler)

    # Generate an RSA key and a private-key-decryption-object (for use with the server; each peer will get its own decryption object)
    my_rsa_priv = RSA.generate(RSA_KEY_SIZE)
    my_rsa_pub = my_rsa_priv.public_key()
    server_priv_crypter = PKCS1_OAEP.new(my_rsa_priv)
    # print(f"(CLIENT) Client {my_name} generated RSA key -- public: {my_rsa_pub.exportKey()}")
    
    # Create a listener socket and give it a thread to live in
    # This is the socket that other clients can connect to us from
    _listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _listen_socket.settimeout(3)
    while listen_port == 0: # Try random ports until finding an unoccupied one
        try:
            listen_port = random.randint(20000, 50000)
            _listen_socket.bind(("0.0.0.0", listen_port))
        except OSError:
            listen_port = 0
    _listen_socket.listen(10)
    listener_thread = threading.Thread(target = listen_for_peers, args = (_listen_socket,))
    listener_thread.start()
    print(f"(CLIENT) Client {my_name} listening for peers on port {listen_port}")

    # --- Connect to the server ---
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(3)
    server_socket.connect((server_ip, SERVER_PORT))

    # Send the server our name, public key, and listen port, waiting for OKs in between each
    server_socket.send(f"{my_name}".encode('utf-8'))
    if (server_socket.recv(1024).decode('utf-8') != "OK"):
        crash_handler()
    server_socket.send(f"{listen_port}".encode('utf-8'))
    if (server_socket.recv(1024).decode('utf-8') != "OK"):
        crash_handler()
    server_socket.send(my_rsa_pub.exportKey())

    # Server will send its public RSA key. Generate a crypter object for it and send OK
    _server_rsa_pub = server_socket.recv(1024)
    server_rsa_pub = RSA.importKey(_server_rsa_pub)
    server_pub_crypter = PKCS1_OAEP.new(server_rsa_pub)
    server_socket.send("OK".encode('utf-8'))

    # Server will send symmetric key (encrypted using my public key)
    _server_sym_key_enc = server_socket.recv(1024)
    server_sym_key = server_priv_crypter.decrypt(_server_sym_key_enc)

    # Generate an AES encrypter object using the symmetric key, and send the server our nonce, encrypted using the server's public key
    server_sym_encrypter = AES.new(server_sym_key, AES.MODE_GCM)
    server_socket.send(server_pub_crypter.encrypt(server_sym_encrypter.nonce))

    # Server will send its nonce (encoded using our public key). Use it to generate our symmetric decrypter
    _server_nonce_enc = server_socket.recv(1024)
    server_nonce = server_priv_crypter.decrypt(_server_nonce_enc)
    server_sym_decrypter = AES.new(server_sym_key, AES.MODE_GCM, nonce = server_nonce)

    # Send OK
    server_socket.send("OK".encode('utf-8'))

    # Create Connection object for the server
    server = Connection(server_socket, '__SERVER__', 0, 0, server_rsa_pub, server_pub_crypter, server_priv_crypter, server_sym_encrypter, server_sym_decrypter)
    print(f"(CLIENT) Client {my_name} registered to server")

    # Initialize server communications (flows 2 and 3)
    t_last_flow2 = time.time()
    t_last_flow3 = t_last_flow2
    while running:
        t = time.time()

        # --- FLOW 2 --- 
        if ((t - t_last_flow2) > 10):
            # Update connections to other peers on the network: establish new connections & remove old ones
            t_last_flow2 = t

            # Send LIST_CLIENTS request to server
            running = running and server.send("LIST_CLIENTS")
            # Wait for response. If response is empty: server has shut down
            # (Note that we can never receive an empty client list here, since we ourselves are connected)
            msg = server.recv()
            running = running and (msg != '')

            # Make sure we are connected to every single client the server tells us exists
            for client_name in msg.split(','):

                # If this is a client we haven't connected to yet, and it's not us, then request its address from the server
                if ((client_name not in connections) and (client_name != my_name)):
                    running = server.send(f"GET_CLIENT_ADDR {client_name}")
                    caddr = server.recv()
                    running = running and (caddr != '')
                    if (caddr == "ERROR") or (caddr == ''): break

                    # Connect to the new client
                    try:
                        peer_ip, peer_port = caddr.split(',')
                        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        peer_socket.connect((peer_ip, int(peer_port)))
                        thread = threading.Thread(target = handle_peer, args = (peer_socket, (peer_ip, int(peer_port)), client_name, True))
                        thread.start()
                        peer_threads.append(thread)
                    except Exception as e:
                        print(f"(CLIENT) Client {my_name} failed to connect to {client_name} with caddr = {caddr}: {e}")

            # Remove old connections
            for (client_name, client) in connections.items():
                #TODO: delete any clients which no longer exist
                pass

        # --- FLOW 3 ---
        if ((t - t_last_flow3) > 15):
            t_last_flow3 = t
            # Send a PING message to all peers
            for peer in list(connections.values()):
                if (peer.name == '__SERVER__'): continue
                peer.send("PING")

    server.close()
    listener_thread.join()

    # Close connection to each peer
    for peer in list(connections.values()):
        peer.close()
    print(f"(CLIENT) Client {my_name} sent close request to all peers...")
    for t in peer_threads:
        t.join()

    print(f"(CLIENT) !!! Client {my_name} closed successfully !!!")
