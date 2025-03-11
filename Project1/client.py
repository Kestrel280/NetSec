import sys
import argparse
import socket
import time
import signal
from shared import *

running = True
server = 0 # Initialize server here so that it's globally scoped
my_name = ''

parser = argparse.ArgumentParser()
parser.add_argument("--network", help="Server IP to connect to.", type=str, metavar="{Server IP}", required=True)
parser.add_argument("--name", help="Name to assign to this client.", type=str, metavar="{Client name}", required=True)

def crash_handler(*args):
    global running
    print(f"(CLIENT) Client {my_name} received shutdown signal, shutting down...")
    running = False

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

    # Create the socket and connect to the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(3)
    server_socket.connect((server_ip, SERVER_PORT))
    server = Connection(server_socket, '__SERVER__')

    # Send the server our name & wait for echo response
    server.send(my_name)
    server.recv()

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

                # TODO: Connect to the new client
                try:
                    1+1
                    # ip,port = eval(caddr)
                    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # client_socket.connect((ip,port))
                    # connections[client_name] = Connection(client_socket, client_name)
                    print(f"Connected to {client_name} at {ip}:{port}")

                    # the code is now throwing exception because when the client tries to connect to the other client, there is not listening part
                    # TODO: The client should listen for other client connection request
                except Exception as e:
                    pass
                    # print(f"Failed to connect to {client_name}: {e}")

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
    print(f"(CLIENT) Client {my_name} closed")
