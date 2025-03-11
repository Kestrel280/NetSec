import sys
import argparse
import socket
import time
import atexit
from shared import *

server_socket = 0 # Initialize server_socket here so that it's globally scoped

parser = argparse.ArgumentParser()
parser.add_argument("--network", help="Server IP to connect to.", type=str, metavar="{Server IP}", required=True)
parser.add_argument("--name", help="Name to assign to this client.", type=str, metavar="{Client name}", required=True)

def crash_handler(*args):
    try:
        server_socket.close()
        for client in connected_clients.values():
            client.close()
    except:
        return

if __name__ == '__main__':
    # Extract args from command line
    args = parser.parse_args()
    try:
        server_ip = args.network
        client_name = args.name
    except:
        print("Illegal arguments")
        exit()

    # Register emergency-termination function (to close socket in case of crash)
    atexit.register(crash_handler)

    # Create the socket and connect to the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((server_ip, SERVER_PORT))

    # Send the server our name & wait for echo response
    server_socket.send(client_name.encode('utf-8'))
    server_socket.recv(1024)

    # --- FLOW 2 ---
    # (1) Every 10 seconds (at minimum), send a "LIST_CLIENTS" message to the server
    #   The server will respond with a list of client names
    # (2) For each client name, check if we have already registered that client
    #   If we haven't, then send a "GET_CLIENT_ADDR [NAME]" msg to server,
    #   and connect to the address it responds with
    # (3) Finally, check our list of connected clients:
    #   if we have an "extras" (e.g. clients that we have registered, but the server doesn't),
    #   close them. They must have disconnected
    while True:
        t = time.time()
        # (1) - Complete
        server_socket.send("LIST_CLIENTS".encode('utf-8'))
        msg = server_socket.recv(1024).decode('utf-8')

        # (2) - In progress
        for client_name in msg.split(','):
            if client_name not in connected_clients:
                server_socket.send(f"GET_CLIENT_ADDR {client_name}".encode('utf-8'))
                caddr = server_socket.recv(1024).decode('utf-8')
                # TODO: Connect to caddr, register client
                if caddr != "ERROR":
                    try:
                        ip,port = eval(caddr)
                        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client_socket.connect((ip,port))
                        connected_clients[client_name] = Client(client_socket, client_name)
                        print(f"Connected to {client_name} at {ip}:{port}")

                        # the code is now throwing exception because when the client tries to connect to the other client, there is not listening part
                        # TODO: The client should listen for other client connection request
                    except Exception as e:
                        print(f"Failed to connect to {client_name}: {e}")

        # (3)
        for (client_name, client) in connected_clients.items():
            #TODO: delete any clients which no longer exist
            pass

        # Delay until the next 10 second interval is reached
        delay = max(0.0, 10.0 - time.time() + t)
        time.sleep(delay)

    print("-- Client escaped main loop!!! --")
    server_socket.close()
