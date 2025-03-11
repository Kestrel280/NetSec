import sys
import argparse
import socket
import time
import signal
import random
import threading
from shared import *

running = True
listen_port = 0
listener_thread = 0
server = 0
my_name = ''

parser = argparse.ArgumentParser()
parser.add_argument("--network", help="Server IP to connect to.", type=str, metavar="{Server IP}", required=True)
parser.add_argument("--name", help="Name to assign to this client.", type=str, metavar="{Client name}", required=True)

def crash_handler(*args):
    global running
    print(f"(CLIENT) Client {my_name} received shutdown signal, shutting down...")
    running = False

def listen_for_peers(listen_socket):
    while running:
        try:
            peer_socket, peer_address = listen_socket.accept()
            peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except TimeoutError:
            pass
        except Exception as e:
            print("(CLIENT) Error accepting new peer")
            print(e)

    listen_socket.close()
    print(f"(CLIENT) Client {my_name} no longer accepting new connections...")

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

    # Create the socket and connect to the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(3)
    server_socket.connect((server_ip, SERVER_PORT))
    server = Connection(server_socket, '__SERVER__', 0, 0)

    # Send the server our name & wait for echo response
    server.send(f"{my_name}, {listen_port}")
    server.recv()
    print(f"(CLIENT) Client {my_name} registered to server")

    # --- FLOW 2 ---
    # (1) Every 10 seconds (at minimum), send a "LIST_CLIENTS" message to the server
    #   The server will respond with a list of client names
    # (2) For each client name, check if we have already registered that client
    #   If we haven't, then send a "GET_CLIENT_ADDR [NAME]" msg to server,
    #   and connect to the address it responds with
    # (3) Finally, check our list of connected clients:
    #   if we have an "extras" (e.g. clients that we have registered, but the server doesn't),
    #   close them. They must have disconnected
    while running:
        t = time.time()
        # (1) - Complete
        # Send LIST_CLIENTS request
        running = server.send("LIST_CLIENTS")
        # Wait for response
        # If response is empty: server has shut down
        # Note that we can never receive an empty client list here, since we ourselves are connected
        msg = server.recv()
        running = (msg != '')

        # (2) - In progress
        for client_name in msg.split(','):

            # If this is a client we haven't connected to yet,
            #   and it's not us,
            #   then request its details from the server
            if ((client_name not in connections) and (client_name != my_name)):
                running = server.send(f"GET_CLIENT_ADDR {client_name}")
                caddr = server.recv()
                running = (caddr != '')
                if (caddr == "ERROR") or (caddr == ''): break

                # Connect to the new client
                try:
                    cip, cport = caddr.split(',')
                    print(f"CIP: {cip} | CPORT: {cport}")
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect((cip, int(cport)))
                    connections[client_name] = Connection(client_socket, client_name, cip, cport)
                    print(f"(CLIENT) Client {my_name} connected to {client_name} at {cip}:{cport}")
                except Exception as e:
                    print(f"(CLIENT) Client {my_name} failed to connect to {client_name} with caddr = {caddr}: {e}")

        # (3)
        for (client_name, client) in connections.items():
            #TODO: delete any clients which no longer exist
            pass

        # Delay until the next 10 second interval is reached
        if running:
            delay = max(0.0, 10.0 - time.time() + t)
            time.sleep(delay)
        else:
            break

    server.close()
    listener_thread.join()
    print(f"(CLIENT) Client {my_name} closed")
