import sys
import socket
import threading
import signal
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from shared import *

# Globals
running = True          # Flag used to manage running state
listener_socket = 0     # Socket which is listening for connections from clients
client_threads = []     # Array of threads which are managing peer clients

# Function to shut down the server -- can be called manually, or by signal interrupt
def crash_handler(*args):
    global running
    print("(SERVER) Server received shutdown signal, shutting down...")
    running = False

def handle_client(socket, addr):
    '''
    Thread function to run which handles:
        1. Establishing connection with a client (after socket has been created)
        2. Messaging with client
    '''
    # Client will send name, then listen port, then its public key
    # Respond with our public key and wait for OK
    client_name = socket.recv(1024).decode('utf-8')
    socket.send("OK".encode('utf-8'))
    client_listen_port = socket.recv(1024).decode('utf-8')
    socket.send("OK".encode('utf-8'))
    _client_pub_key = socket.recv(1024).decode('utf-8')
    client_pub_key = RSA.importKey(_client_pub_key)
    socket.send(my_rsa_pub.exportKey())
    if (socket.recv(1024).decode('utf-8') != "OK"):
        crash_handler()

    # Generate a symmetric key for use with this client
    # Generate a crypter object for the client's public key and use it to encrypt the symmetric key
    # Encrypt the symmetric key using the client's public key
    client_sym_key = os.urandom(32)
    _client_sym_key_enc = PKCS1_OAEP.new(client_pub_key).encrypt(client_sym_key)

    # Send the encrypted symmetric key to the client, receive OK
    socket.send(_client_sym_key_enc)

    if (socket.recv(1024).decode('utf-8') != "OK"):
        crash_handler()

    # All set -- create a Connection object to store all the info on this client
    try:
        client = Connection(socket, client_name, addr[0], client_listen_port, client_pub_key, client_sym_key)
    except NameError as e:
        print(f"(SERVER) Server received connection request from client {client_name}, but a client with that name already exists")
        print(e)
        return
    print(f"(SERVER) Server established connection with client {client_name}")

    # Enter main loop
    # When the client closes the socket, it will send an empty message
    # So, our while loop is structured to terminate when it receives an empty message
    msg = client.recv()
    while msg:
        # First (or only) token of message is the command
        cmd = msg.split(' ')[0]
        response = 'OK'
        _enc = True

        # Dispatch logic depending on what command was received
        # (Note: no fallthrough in Python match-case statements, so no breaks)
        match cmd:
            case 'LIST_CLIENTS':
                #response = 'LIST_CLIENTS PLACEHOLDER'
                #returning the names to the client
                response = ",".join(connections.keys())

            case 'GET_CLIENT_ADDR': 
                # There should be an argument provided, with the name of the desired client's
                try: 
                    arg = msg.split(' ')[1]
                    if arg in connections:
                        response = f"{connections[arg].ip}, {connections[arg].port}"
                    else: raise KeyError(f"No details available for '{arg}'")
                except Exception as e: 
                    print(f"(SERVER) Error getting details for {arg}, requested by {client.name}: {e}")
                    response = 'ERROR'

            case 'GET_PUBLIC_KEY':
                # There should be an argument provided, with the name of the desired client
                try: 
                    arg = msg.split(' ')[1]
                    if arg in connections:
                        response = connections[arg].connection_pub_key.exportKey()
                        _enc = False
                    else: raise KeyError(f"No details available for '{arg}'")
                except Exception as e: 
                    print(f"(SERVER) Error getting details for {arg}, requested by {client.name}: {e}")
                    response = 'ERROR'

        client.send(response, encutf8 = _enc)
        print("(SERVER) Received msg \"{}\" from Client {}; responded '{}'".format(msg if len(msg) < 50 else f"{msg[:47]}...", client_name, response if len(response) < 50 else f"{response[:47]}..."))
        
        # Await next message (or empty message, if client closes connection)
        msg = client.recv()

    # Out of the while loop -- empty message was received, so client must have closed the connection
    # Close the socket on our end (in certain cases, this could be redundant/a double-close, which is OK)
    print(f"(SERVER) Client {client.name} has closed connection: closing on our end too")
    client.close()
    return

if __name__ == '__main__':
    # Register emergency-termination function (to close sockets in case of crash)
    signal.signal(signal.SIGINT, crash_handler)
    signal.signal(signal.SIGTERM, crash_handler)

    # Generate an RSA key and store it as a Connection class attribute
    my_rsa_priv = RSA.generate(RSA_KEY_SIZE)
    my_rsa_pub = my_rsa_priv.public_key()
    Connection.my_priv_key = my_rsa_priv
    Connection.my_pub_key = my_rsa_pub
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
    #   start a new thread running handle_client for the new client
    while running:
        try:
            client_socket, client_address = listener_socket.accept()
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            thread = threading.Thread(target = handle_client, args = (client_socket, client_address))
            thread.start()
            client_threads.append(thread)
        except TimeoutError: # Listener socket will timeout every 3 seconds to check if running is still True
            pass
        except Exception as e:
            print("(SERVER) Error accepting new client, terminating!")
            print(e)
            running = False

    # For whatever reason, 'running' is now false: shut down the server
    
    # Close the listener socket
    listener_socket.close()
    print(f"(SERVER) Server no longer accepting new connections...")

    # Close connection to each client
    for client in list(connections.values()):
        client.close()
    print(f"(SERVER) Server sent close request to all clients...")
    for t in client_threads:
        t.join()
    print(f"(SERVER) !!! Server closed successfully !!!")
