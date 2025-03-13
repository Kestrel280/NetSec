import sys
import socket
import threading
import signal
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from shared import *

listener_socket = 0 # Initialize listener_socket here so that it's globally scoped
running = True
client_threads = []

def crash_handler(*args):
    global running
    print("(SERVER) Server received shutdown signal, shutting down...")
    running = False

def handle_client(socket, addr):
    # On connection established, 3 messages -- name, listen port, then public key
    client_name = socket.recv(1024).decode('utf-8')
    socket.send("OK".encode('utf-8'))
    client_listen_port = socket.recv(1024).decode('utf-8')
    socket.send("OK".encode('utf-8'))
    _client_pub_key = socket.recv(1024).decode('utf-8')
    # Don't send OK here -- gonna send keys next
    print(f"client_name: {client_name}")
    print(f"client_listen_port: {client_listen_port}")
    print(f"_client_pub_key: {_client_pub_key}")
    client_pub_key = RSA.importKey(_client_pub_key)

    # Generate a symmetric key to use for this client
    client_aes_key = os.urandom(16)

    # Encrypt the symmetric key using the client's public key
    client_pub_enc_obj = PKCS1_OAEP.new(client_pub_key)
    client_aes_key_enc = client_pub_enc_obj.encrypt(client_aes_key)

    # Send my public key + the encrypted symmetric key to the client 
    socket.send(_exp_my_rsa_pub)
    if (socket.recv(1024).decode('utf-8') != "OK"):
        crash_handler()
    socket.send(client_aes_key_enc)
    if (socket.recv(1024).decode('utf-8') != "OK"):
        crash_handler()

    client = Connection(socket, client_name, addr[0], client_listen_port)
    if client is None: return # If connection constructor returned None, the connection couldn't be created; end this thread immediately

    print(f"(SERVER) Client thread spawned for new client {client.name}")

    # Enter main loop
    # When the client closes the socket, it will send an empty message
    # So, our while loop is structured to terminate when it receives an empty message
    msg = client.recv()
    while msg:
        # First (or only) token of message is the command
        cmd = msg.split(' ')[0]

        response = 'OK'
        # Dispatch logic depending on what command was received
        # (Note: no fallthrough in Python match-case statements, so no breaks)
        match cmd:
            case 'LIST_CLIENTS':
                #response = 'LIST_CLIENTS PLACEHOLDER'
                #returning the names to the client
                response = ",".join(connections.keys())
            case 'GET_CLIENT_ADDR': 
                # There should be an argument provided
                try: 
                    arg = msg.split(' ')[1]
                    if arg in connections:
                        response = f"{connections[arg].ip}, {connections[arg].port}"
                    else:
                        print("(SERVER) Client {client.name} requested details on {arg}, but we don't have that info")
                        response = 'ERROR'
                except Exception as e: 
                    print(f"(SERVER) Error getting details for {arg}, requested by {client.name}")
                    response = 'ERROR'
        client.send(response)
        
        print(f"(SERVER) Received msg '{msg}' from Client {client.name}; responded '{response}'")
        msg = client.recv()

    # Out of the while loop -- empty message was received, so client must have closed the connection
    # Close the socket on our end
    #   (In certain cases, this could be redundant/a double-close, which is OK)
    print(f"(SERVER) Client {client.name} has closed connection: closing on our end too")
    client.close()
    return

if __name__ == '__main__':
    # Register emergency-termination function (to close sockets in case of crash)
    signal.signal(signal.SIGINT, crash_handler)
    signal.signal(signal.SIGTERM, crash_handler)

    # Generate an RSA key
    my_rsa_priv = RSA.generate(RSA_KEY_SIZE)
    my_rsa_pub = my_rsa_priv.public_key()
    _exp_my_rsa_pub = my_rsa_pub.exportKey()
    print(f"(SERVER) Server generated RSA key")

    # Create and initialize the listener socket
    # The role of this socket is just to listen for incoming connections
    # When a new connection request is received, it creates a new thread
    #   to handle the new client
    server_ip = socket.gethostbyname(socket.gethostname())
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.settimeout(3)
    listener_socket.bind(("0.0.0.0", SERVER_PORT)) # 0.0.0.0 is to listen for any connections
    listener_socket.listen(10)

    print(f"(SERVER) Network started on {server_ip}:{SERVER_PORT}")

    # Start listening on the listener socket
    # Whenever a new connection is established,
    #   start a new thread running handle_client
    #   for the new client
    while running:
        try:
            client_socket, client_address = listener_socket.accept()
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            thread = threading.Thread(target = handle_client, args = (client_socket, client_address))
            thread.start()
            client_threads.append(thread)
        except TimeoutError:
            pass
        except Exception as e:
            print("(SERVER) Error accepting new client, terminating!")
            print(e)
            running = False

    listener_socket.close()
    print(f"(SERVER) Server no longer accepting new connections...")

    for client in list(connections.values()):
        client.close()

    print(f"(SERVER) Server sent close request to all clients...")

    for t in client_threads:
        t.join()
    print(f"(SERVER) Server closed successfully")
